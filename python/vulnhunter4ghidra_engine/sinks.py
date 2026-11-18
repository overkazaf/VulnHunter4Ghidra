from .models import Sink, SinkType

SINK_SIGNATURES: dict[str, tuple[SinkType, str, int]] = {
    # (sink_type, CWE, vulnerable_arg_index)
    # Buffer overflow sinks
    "memcpy":   (SinkType.BUFFER_OVERFLOW, "CWE-120", 0),
    "memmove":  (SinkType.BUFFER_OVERFLOW, "CWE-120", 0),
    "strcpy":   (SinkType.BUFFER_OVERFLOW, "CWE-120", 0),
    "strncpy":  (SinkType.BUFFER_OVERFLOW, "CWE-120", 0),
    "strcat":   (SinkType.BUFFER_OVERFLOW, "CWE-120", 0),
    "strncat":  (SinkType.BUFFER_OVERFLOW, "CWE-120", 0),
    "gets":     (SinkType.BUFFER_OVERFLOW, "CWE-120", 0),
    "read":     (SinkType.BUFFER_OVERFLOW, "CWE-120", 1),
    "recv":     (SinkType.BUFFER_OVERFLOW, "CWE-120", 1),
    "recvfrom": (SinkType.BUFFER_OVERFLOW, "CWE-120", 1),
    # Format string sinks
    "printf":   (SinkType.FORMAT_STRING, "CWE-134", 0),
    "sprintf":  (SinkType.FORMAT_STRING, "CWE-134", 1),
    "fprintf":  (SinkType.FORMAT_STRING, "CWE-134", 1),
    "snprintf": (SinkType.FORMAT_STRING, "CWE-134", 2),
    "syslog":   (SinkType.FORMAT_STRING, "CWE-134", 1),
    # Use-after-free / double-free sinks
    "free":     (SinkType.USE_AFTER_FREE, "CWE-416", 0),
    # Command injection sinks
    "system":   (SinkType.COMMAND_INJECTION, "CWE-78", 0),
    "popen":    (SinkType.COMMAND_INJECTION, "CWE-78", 0),
    "execve":   (SinkType.COMMAND_INJECTION, "CWE-78", 0),
    "execvp":   (SinkType.COMMAND_INJECTION, "CWE-78", 0),
}


def identify_sinks(
    func_addr: int,
    func_name: str,
    callsites: list[dict],
) -> list[Sink]:
    """Identify sinks from call sites within a function.

    Each callsite dict has: address (int), callee_name (str).
    """
    sinks = []
    for cs in callsites:
        callee = cs.get("callee_name", "")
        addr = cs["address"]
        if callee in SINK_SIGNATURES:
            sink_type, cwe, vuln_arg = SINK_SIGNATURES[callee]
            sinks.append(Sink(
                address=addr,
                func_addr=func_addr,
                func_name=func_name,
                callee_name=callee,
                sink_type=sink_type,
                cwe=cwe,
                vulnerable_arg_index=vuln_arg,
            ))
    return sinks


def get_sink_functions() -> set[str]:
    """Return the set of all known sink function names."""
    return set(SINK_SIGNATURES.keys())


def get_cwe_for_function(func_name: str) -> str | None:
    """Return the CWE ID for a known sink function, or None."""
    entry = SINK_SIGNATURES.get(func_name)
    return entry[1] if entry else None
