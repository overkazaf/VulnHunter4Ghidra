from .models import Sink, SinkType
from .rules import (
    DEFAULT_SINK_SPECS,
    GLOBAL_RULES,
    RuleRegistry,
    canonical_func_name,
    normalize_func_name,
)

SINK_SIGNATURES: dict[str, tuple[SinkType, str, int]] = {
    name: (spec.sink_type, spec.cwe, spec.vulnerable_arg_index)
    for name, spec in DEFAULT_SINK_SPECS.items()
}


def identify_sinks(
    func_addr: int,
    func_name: str,
    callsites: list[dict],
    registry: RuleRegistry | None = None,
) -> list[Sink]:
    """Identify sinks from call sites within a function.

    Each callsite dict has: address (int), callee_name (str).
    Normalizes platform/PLT/Fortify function decorations automatically.
    """
    reg = registry or GLOBAL_RULES
    sinks = []
    for cs in callsites:
        raw_callee = cs.get("callee_name", "")
        callee, is_fortified = normalize_func_name(raw_callee)
        addr = cs["address"]

        custom_spec = reg.custom_sink_addrs.get(addr)
        if custom_spec is not None:
            sinks.append(Sink(
                address=addr,
                func_addr=func_addr,
                func_name=func_name,
                callee_name=callee or raw_callee or "custom_sink",
                sink_type=custom_spec.sink_type,
                cwe=custom_spec.cwe,
                vulnerable_arg_index=custom_spec.vulnerable_arg_index,
                tainted_arg_indices=custom_spec.tainted_arg_indices,
                is_fortified=is_fortified,
            ))
            continue

        spec = reg.sinks.get(callee)
        if spec is not None:
            sinks.append(Sink(
                address=addr,
                func_addr=func_addr,
                func_name=func_name,
                callee_name=callee,
                sink_type=spec.sink_type,
                cwe=spec.cwe,
                vulnerable_arg_index=spec.vulnerable_arg_index,
                tainted_arg_indices=spec.tainted_arg_indices,
                is_fortified=is_fortified,
            ))
    return sinks


def get_sink_functions(registry: RuleRegistry | None = None) -> set[str]:
    """Return the set of all known sink function names."""
    reg = registry or GLOBAL_RULES
    return set(reg.sources and reg.sinks.keys())


def get_cwe_for_function(func_name: str, registry: RuleRegistry | None = None) -> str | None:
    """Return the CWE ID for a known sink function, or None."""
    reg = registry or GLOBAL_RULES
    canon = canonical_func_name(func_name)
    spec = reg.sinks.get(canon)
    return spec.cwe if spec else None
