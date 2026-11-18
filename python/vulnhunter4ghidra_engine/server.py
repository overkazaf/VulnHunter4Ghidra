import argparse
import logging
import socket
import threading

from .engine import VulnHunterEngine
from .protocol import parse_command, ok, error, progress

HOST = "127.0.0.1"
PORT = 13372

logging.basicConfig(
    level=logging.INFO,
    format="[vulnhunter4ghidra] %(levelname)s %(message)s",
)
logger = logging.getLogger("vulnhunter4ghidra")

HANDLERS = {
    "init": lambda eng, p: eng.init(p["binary_path"]),
    "scan_function": lambda eng, p: eng.scan_function(
        func_addr=int(p["func_addr"], 16) if isinstance(p["func_addr"], str) else p["func_addr"],
        func_name=p["func_name"],
        callsites=p.get("callsites", []),
        params=p.get("params", []),
        is_exported=p.get("is_exported", False),
    ),
    "get_findings": lambda eng, p: {"findings": eng.get_findings()},
    "get_sources": lambda eng, p: {"sources": eng.get_sources()},
    "get_sinks": lambda eng, p: {"sinks": eng.get_sinks()},
}


def handle_client(conn: socket.socket, engine: VulnHunterEngine):
    with conn.makefile("r", encoding="utf-8") as reader, \
         conn.makefile("w", encoding="utf-8") as writer:
        for line in reader:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = parse_command(line)
                logger.info("CMD: %s", cmd.type)
                if cmd.type == "analyze_taint":
                    max_depth = cmd.params.get("max_depth", 5)
                    result = engine.analyze_taint(max_depth=max_depth)
                    resp = ok(result)
                elif cmd.type == "scan_functions":
                    functions = cmd.params.get("functions", [])
                    results = []
                    for i, func_info in enumerate(functions):
                        func_result = engine.scan_function(
                            func_addr=int(func_info["func_addr"], 16) if isinstance(func_info["func_addr"], str) else func_info["func_addr"],
                            func_name=func_info["func_name"],
                            callsites=func_info.get("callsites", []),
                            params=func_info.get("params", []),
                            is_exported=func_info.get("is_exported", False),
                        )
                        results.append(func_result)
                        if i % 20 == 0:
                            writer.write(progress({"scanned": i, "total": len(functions)}).to_json() + "\n")
                            writer.flush()
                    resp = ok({"results": results})
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


def main():
    parser = argparse.ArgumentParser(description="VulnHunter4Ghidra analysis engine")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger("vulnhunter4ghidra").setLevel(logging.DEBUG)

    engine = VulnHunterEngine()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)
    logger.info("VulnHunter4Ghidra engine listening on %s:%d", args.host, args.port)

    try:
        while True:
            conn, addr = server.accept()
            logger.info("Client connected from %s", addr)
            thread = threading.Thread(target=handle_client, args=(conn, engine), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
