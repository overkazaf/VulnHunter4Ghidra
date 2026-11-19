import argparse
import hmac
import logging
import os
import secrets
import socket
import sys
import threading
from typing import TextIO

from .engine import VulnHunterEngine
from .protocol import error, ok, parse_command, progress

HOST = "127.0.0.1"
PORT = 13372

logger = logging.getLogger("vulnhunter4ghidra")


def _parse_int_or_none(val) -> int | None:
    if val is None:
        return None
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s:
        return None
    return int(s, 16) if s.startswith(("0x", "0X")) else int(s)


HANDLERS = {
    "ping": lambda eng, p: {"pong": True},
    "init": lambda eng, p: eng.init(p["binary_path"], base_addr=p.get("base_addr")),
    "clear_scan": lambda eng, p: eng.clear_scan(),
    "cancel": lambda eng, p: eng.cancel(),
    "load_rules": lambda eng, p: eng.load_rules(p["path"]),
    "mark_custom": lambda eng, p: eng.mark_custom_node(
        role=p["role"],
        func_name=p.get("func_name"),
        address=_parse_int_or_none(p.get("address")),
        cwe=p.get("cwe", "CWE-120"),
        sink_type=p.get("sink_type", "buffer_overflow"),
        vulnerable_arg_index=int(p.get("vulnerable_arg_index", 0)),
    ),
    "scan_function": lambda eng, p: eng.scan_function(
        func_addr=_parse_int_or_none(p["func_addr"]),
        func_name=p["func_name"],
        callsites=p.get("callsites", []),
        params=p.get("params", []),
        is_exported=p.get("is_exported", False),
    ),
    "get_findings": lambda eng, p: {"findings": eng.get_findings()},
    "get_sources": lambda eng, p: {"sources": eng.get_sources()},
    "get_sinks": lambda eng, p: {"sinks": eng.get_sinks()},
}


def serve_streams(
    reader: TextIO,
    writer: TextIO,
    engine: VulnHunterEngine,
    auth_token: str | None = None,
) -> None:
    """Process JSON-line commands from `reader` and write responses to `writer`."""
    for raw_line in reader:
        line = raw_line.strip()
        if not line:
            continue
        try:
            cmd = parse_command(line)
            if auth_token is not None:
                provided = cmd.token or ""
                if not hmac.compare_digest(provided, auth_token):
                    writer.write(error("Unauthorized engine session token").to_json() + "\n")
                    writer.flush()
                    continue

            logger.info("CMD: %s", cmd.type)
            if cmd.type == "shutdown":
                writer.write(ok({"shutdown": True}).to_json() + "\n")
                writer.flush()
                break
            elif cmd.type == "analyze_taint":
                max_depth = int(cmd.params.get("max_depth", 5))
                func_filter = _parse_int_or_none(cmd.params.get("func_addr"))
                verify = bool(cmd.params.get("verify", False))
                result = engine.analyze_taint(
                    max_depth=max_depth,
                    func_filter=func_filter,
                    verify_symbolic=verify,
                ) if "verify_symbolic" in engine.analyze_taint.__code__.co_varnames else engine.analyze_taint(
                    max_depth=max_depth,
                    func_filter=func_filter,
                )
                resp = ok(result)
            elif cmd.type == "export_sarif":
                if hasattr(engine, "export_sarif"):
                    resp = ok({"sarif": engine.export_sarif()})
                else:
                    resp = error("SARIF exporter not available")
            elif cmd.type == "scan_functions":
                functions = cmd.params.get("functions", [])
                if cmd.params.get("replace", True):
                    engine.clear_scan()
                results = []
                total = len(functions)
                for i, func_info in enumerate(functions):
                    func_result = engine.scan_function(
                        func_addr=_parse_int_or_none(func_info["func_addr"]),
                        func_name=func_info["func_name"],
                        callsites=func_info.get("callsites", []),
                        params=func_info.get("params", []),
                        is_exported=func_info.get("is_exported", False),
                    )
                    results.append(func_result)
                    if i % 20 == 0 or i + 1 == total:
                        writer.write(progress({"scanned": i + 1, "total": total}).to_json() + "\n")
                        writer.flush()
                resp = ok({
                    "functions_scanned": total,
                    "total_sources": len(engine.get_sources()),
                    "total_sinks": len(engine.get_sinks()),
                    "results": results,
                })
            else:
                handler = HANDLERS.get(cmd.type)
                if handler is None:
                    resp = error(f"Unknown command: {cmd.type}")
                else:
                    result = handler(engine, cmd.params)
                    resp = ok(result)
        except Exception as e:
            logger.exception("Error handling command")
            resp = error(str(e))
        writer.write(resp.to_json() + "\n")
        writer.flush()


def handle_client(conn: socket.socket, auth_token: str | None = None):
    # Isolated VulnHunterEngine per client connection prevents cross-session state corruption
    client_engine = VulnHunterEngine()
    with conn, \
         conn.makefile("r", encoding="utf-8") as reader, \
         conn.makefile("w", encoding="utf-8") as writer:
        serve_streams(reader, writer, client_engine, auth_token=auth_token)


def run_stdio_server(auth_token: str | None = None) -> None:
    """Run dedicated single-parent JSON-line RPC server over stdin/stdout.

    Duplicates fd 1 for protocol output and redirects process stdout -> stderr so
    native libraries (VEX/Z3/Unicorn) cannot corrupt the JSON-line stream.
    """
    proto_fd = os.dup(sys.stdout.fileno())
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    sys.stdout = sys.stderr

    engine = VulnHunterEngine()
    with os.fdopen(proto_fd, "w", encoding="utf-8", buffering=1) as proto_writer:
        logger.info("VulnHunter4Ghidra engine ready in stdio mode")
        serve_streams(sys.stdin, proto_writer, engine, auth_token=auth_token)


def main():
    parser = argparse.ArgumentParser(description="VulnHunter4Ghidra analysis engine")
    parser.add_argument("--stdio", action="store_true", help="Communicate via stdin/stdout JSON-lines")
    parser.add_argument("--port", type=int, default=PORT, help="TCP port (0 for dynamic free port)")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--auth-token", default=None, help="Require session token on every command")
    parser.add_argument("--generate-token", action="store_true", help="Generate and print a session token")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[vulnhunter4ghidra] %(levelname)s %(message)s",
    )

    token = args.auth_token
    if args.generate_token and not token:
        token = secrets.token_hex(16)

    if args.stdio:
        run_stdio_server(auth_token=token)
        return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    bound_host, bound_port = server.getsockname()[:2]
    server.listen(4)
    logger.info("VulnHunter4Ghidra engine listening on %s:%d", bound_host, bound_port)
    if args.generate_token:
        logger.info("VULNHUNTER_SESSION port=%d token=%s", bound_port, token)

    try:
        while True:
            conn, addr = server.accept()
            logger.info("Client connected from %s", addr)
            thread = threading.Thread(
                target=handle_client,
                args=(conn, token),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
