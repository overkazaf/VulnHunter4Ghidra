from .models import Source, SourceType

INPUT_FUNCTIONS: dict[str, SourceType] = {
    "recv": SourceType.RECV,
    "recvfrom": SourceType.RECV,
    "recvmsg": SourceType.RECV,
    "read": SourceType.READ,
    "pread": SourceType.READ,
    "fread": SourceType.FILE_READ,
    "fgets": SourceType.FGETS,
    "gets": SourceType.FGETS,
    "scanf": SourceType.SCANF,
    "sscanf": SourceType.SCANF,
    "fscanf": SourceType.SCANF,
    "getenv": SourceType.ENV,
}

BUFFER_PARAM_TYPES = frozenset({
    "void *", "byte *", "char *", "uchar *",
    "uint8_t *", "int8_t *", "unsigned char *",
})


def identify_sources_from_callsites(
    func_addr: int,
    func_name: str,
    callsites: list[dict],
) -> list[Source]:
    """Identify sources from call sites within a function.

    Each callsite dict has: address (int), callee_name (str).
    """
    sources = []
    for cs in callsites:
        callee = cs.get("callee_name", "")
        addr = cs["address"]
        if callee in INPUT_FUNCTIONS:
            sources.append(Source(
                address=addr,
                func_addr=func_addr,
                func_name=func_name,
                source_type=INPUT_FUNCTIONS[callee],
                description=f"Call to {callee}()",
            ))
    return sources


def identify_sources_from_params(
    func_addr: int,
    func_name: str,
    params: list[dict],
    is_exported: bool = False,
) -> list[Source]:
    """Identify sources from function parameters.

    Each param dict has: index (int), name (str), type (str).
    Exported functions with buffer-type parameters are sources.
    """
    sources = []
    for p in params:
        ptype = p.get("type", "")
        if ptype in BUFFER_PARAM_TYPES or (is_exported and ptype.endswith("*")):
            sources.append(Source(
                address=func_addr,
                func_addr=func_addr,
                func_name=func_name,
                source_type=SourceType.FUNC_PARAM,
                description=f"Parameter {p['index']}: {p.get('name', '?')} ({ptype})",
                param_index=p["index"],
            ))
    return sources


def identify_argv_source(
    func_addr: int,
    func_name: str,
    params: list[dict],
) -> Source | None:
    """Identify argv source in main-like functions."""
    if func_name not in ("main", "_main", "entry"):
        return None
    for p in params:
        if p.get("name") in ("argv", "args") or p.get("type") == "char * *":
            return Source(
                address=func_addr,
                func_addr=func_addr,
                func_name=func_name,
                source_type=SourceType.ARGV,
                description="argv from main()",
                param_index=p["index"],
            )
    return None
