from .models import Source, SourceType
from .rules import (
    DEFAULT_SOURCE_SPECS,
    GLOBAL_RULES,
    RuleRegistry,
    canonical_func_name,
)

INPUT_FUNCTIONS: dict[str, SourceType] = {
    name: spec.source_type for name, spec in DEFAULT_SOURCE_SPECS.items()
}

BUFFER_PARAM_TYPES = frozenset({
    "void *", "byte *", "char *", "uchar *",
    "uint8_t *", "int8_t *", "unsigned char *",
    "const char *", "const void *", "const uint8_t *",
})


def get_source_functions(registry: RuleRegistry | None = None) -> set[str]:
    reg = registry or GLOBAL_RULES
    return set(reg.sources.keys())


def identify_sources_from_callsites(
    func_addr: int,
    func_name: str,
    callsites: list[dict],
    registry: RuleRegistry | None = None,
) -> list[Source]:
    """Identify sources from call sites within a function.

    Each callsite dict has: address (int), callee_name (str).
    Normalizes platform/PLT/Fortify function decorations automatically.
    """
    reg = registry or GLOBAL_RULES
    sources = []
    for cs in callsites:
        raw_callee = cs.get("callee_name", "")
        callee = canonical_func_name(raw_callee)
        addr = cs["address"]
        if addr in reg.custom_source_addrs:
            sources.append(Source(
                address=addr,
                func_addr=func_addr,
                func_name=func_name,
                source_type=SourceType.READ,
                description=f"Custom source @ {hex(addr)} ({raw_callee or 'site'})",
            ))
            continue
        spec = reg.sources.get(callee)
        if spec is not None:
            sources.append(Source(
                address=addr,
                func_addr=func_addr,
                func_name=func_name,
                source_type=spec.source_type,
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
    Exported functions with buffer/pointer parameters (and size ints paired with buffers)
    are treated as untrusted entry points.
    """
    canon_func = canonical_func_name(func_name)
    if canon_func in ("main", "entry", "start"):
        return []

    sources = []
    for p in params:
        ptype = p.get("type", "").strip()
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
    canon = canonical_func_name(func_name)
    if canon not in ("main", "entry", "wmain"):
        return None
    for p in params:
        ptype = p.get("type", "").replace(" ", "")
        if p.get("name") in ("argv", "args", "envp") or ptype in ("char**", "constchar**", "wchar_t**"):
            return Source(
                address=func_addr,
                func_addr=func_addr,
                func_name=func_name,
                source_type=SourceType.ARGV,
                description="argv from main()",
                param_index=p["index"],
            )
    return None
