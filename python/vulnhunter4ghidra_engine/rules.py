"""Canonical symbol normalization and extensible Source/Sink/Sanitizer rules."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tomllib

from .models import SourceType, SinkType


@dataclass(frozen=True)
class SourceSpec:
    source_type: SourceType
    taints_return: bool = True
    tainted_out_args: tuple[int, ...] = ()


@dataclass(frozen=True)
class SinkSpec:
    sink_type: SinkType
    cwe: str
    vulnerable_arg_index: int
    tainted_arg_indices: tuple[int, ...]
    requires_non_const_arg: int | None = None


_ISOC_PREFIXES = ("__isoc99_", "__isoc23_", "___isoc99_", "___isoc23_")
_IMPORT_PREFIXES = (
    "<EXTERNAL>::",
    "EXTERNAL::",
    "sym.imp.",
    "imp.",
    "plt.",
    "__imp_",
    "_imp__",
)
_PLT_SUFFIXES = ("@plt", "@PLT", "$stub")


def normalize_func_name(name: str) -> tuple[str, bool]:
    """Normalize platform/compiler/disassembler-decorated symbol names.

    Returns:
        (canonical_name, is_fortified)
    """
    if not name:
        return "", False

    s = name.strip()
    if "::" in s and s.startswith(("<EXTERNAL>", "EXTERNAL")):
        s = s.split("::", 1)[1]

    for prefix in _IMPORT_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix):]
            break

    for suffix in _PLT_SUFFIXES:
        if s.endswith(suffix):
            s = s[:-len(suffix)]
            break

    # Strip version suffixes such as memcpy@@GLIBC_2.14
    if "@" in s:
        s = s.split("@", 1)[0]

    for iso_prefix in _ISOC_PREFIXES:
        if s.startswith(iso_prefix):
            s = s[len(iso_prefix):]
            break

    is_fortified = False
    stripped = s.lstrip("_")
    if stripped.endswith("_chk") and len(stripped) > 4:
        is_fortified = True
        stripped = stripped[:-4]

    return stripped, is_fortified


def canonical_func_name(name: str) -> str:
    """Return canonical function name without platform/fortify decorations."""
    canon, _ = normalize_func_name(name)
    return canon


DEFAULT_SOURCE_SPECS: dict[str, SourceSpec] = {
    "recv": SourceSpec(SourceType.RECV, taints_return=True, tainted_out_args=(1,)),
    "recvfrom": SourceSpec(SourceType.RECV, taints_return=True, tainted_out_args=(1,)),
    "recvmsg": SourceSpec(SourceType.RECV, taints_return=True, tainted_out_args=(1,)),
    "WSARecv": SourceSpec(SourceType.RECV, taints_return=False, tainted_out_args=(1,)),
    "InternetReadFile": SourceSpec(SourceType.RECV, taints_return=False, tainted_out_args=(1,)),
    "read": SourceSpec(SourceType.READ, taints_return=True, tainted_out_args=(1,)),
    "pread": SourceSpec(SourceType.READ, taints_return=True, tainted_out_args=(1,)),
    "pread64": SourceSpec(SourceType.READ, taints_return=True, tainted_out_args=(1,)),
    "readv": SourceSpec(SourceType.READ, taints_return=True, tainted_out_args=(1,)),
    "ReadFile": SourceSpec(SourceType.READ, taints_return=False, tainted_out_args=(1,)),
    "fread": SourceSpec(SourceType.FILE_READ, taints_return=True, tainted_out_args=(0,)),
    "fgets": SourceSpec(SourceType.FGETS, taints_return=True, tainted_out_args=(0,)),
    "gets": SourceSpec(SourceType.FGETS, taints_return=True, tainted_out_args=(0,)),
    "getline": SourceSpec(SourceType.STDIN, taints_return=True, tainted_out_args=(0,)),
    "getdelim": SourceSpec(SourceType.STDIN, taints_return=True, tainted_out_args=(0,)),
    "getchar": SourceSpec(SourceType.STDIN, taints_return=True, tainted_out_args=()),
    "fgetc": SourceSpec(SourceType.FILE_READ, taints_return=True, tainted_out_args=()),
    "getc": SourceSpec(SourceType.FILE_READ, taints_return=True, tainted_out_args=()),
    "scanf": SourceSpec(SourceType.SCANF, taints_return=False, tainted_out_args=(1, 2, 3)),
    "sscanf": SourceSpec(SourceType.SCANF, taints_return=False, tainted_out_args=(2, 3)),
    "fscanf": SourceSpec(SourceType.SCANF, taints_return=False, tainted_out_args=(2, 3)),
    "getenv": SourceSpec(SourceType.ENV, taints_return=True, tainted_out_args=()),
    "secure_getenv": SourceSpec(SourceType.ENV, taints_return=True, tainted_out_args=()),
    "GetEnvironmentVariableA": SourceSpec(SourceType.ENV, taints_return=True, tainted_out_args=(1,)),
}

DEFAULT_SINK_SPECS: dict[str, SinkSpec] = {
    # Buffer overflow sinks (CWE-120)
    "memcpy": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1, 2)),
    "memmove": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1, 2)),
    "bcopy": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 1, (0, 2)),
    "strcpy": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1,), requires_non_const_arg=1),
    "wcscpy": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1,), requires_non_const_arg=1),
    "lstrcpyA": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1,), requires_non_const_arg=1),
    "lstrcpyW": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1,), requires_non_const_arg=1),
    "strncpy": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1, 2)),
    "strcat": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1,), requires_non_const_arg=1),
    "wcscat": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1,), requires_non_const_arg=1),
    "lstrcatA": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1,), requires_non_const_arg=1),
    "strncat": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1, 2)),
    "gets": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (0,)),
    "read": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 1, (2,)),
    "recv": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 1, (2,)),
    "recvfrom": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 1, (2,)),
    "vsprintf": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1, 2)),
    "wsprintfA": SinkSpec(SinkType.BUFFER_OVERFLOW, "CWE-120", 0, (1, 2)),
    # Format string sinks (CWE-134)
    "printf": SinkSpec(SinkType.FORMAT_STRING, "CWE-134", 0, (0,), requires_non_const_arg=0),
    "vprintf": SinkSpec(SinkType.FORMAT_STRING, "CWE-134", 0, (0,), requires_non_const_arg=0),
    "sprintf": SinkSpec(SinkType.FORMAT_STRING, "CWE-134", 1, (1,), requires_non_const_arg=1),
    "fprintf": SinkSpec(SinkType.FORMAT_STRING, "CWE-134", 1, (1,), requires_non_const_arg=1),
    "vfprintf": SinkSpec(SinkType.FORMAT_STRING, "CWE-134", 1, (1,), requires_non_const_arg=1),
    "snprintf": SinkSpec(SinkType.FORMAT_STRING, "CWE-134", 2, (2,), requires_non_const_arg=2),
    "vsnprintf": SinkSpec(SinkType.FORMAT_STRING, "CWE-134", 2, (2,), requires_non_const_arg=2),
    "syslog": SinkSpec(SinkType.FORMAT_STRING, "CWE-134", 1, (1,), requires_non_const_arg=1),
    # Pointer lifecycle sinks (CWE-416 / CWE-415)
    "free": SinkSpec(SinkType.USE_AFTER_FREE, "CWE-416", 0, (0,)),
    "cfree": SinkSpec(SinkType.USE_AFTER_FREE, "CWE-416", 0, (0,)),
    "HeapFree": SinkSpec(SinkType.USE_AFTER_FREE, "CWE-416", 2, (2,)),
    # Command injection sinks (CWE-78)
    "system": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 0, (0,), requires_non_const_arg=0),
    "popen": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 0, (0,), requires_non_const_arg=0),
    "_popen": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 0, (0,), requires_non_const_arg=0),
    "execve": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 0, (0, 1), requires_non_const_arg=0),
    "execvp": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 0, (0, 1), requires_non_const_arg=0),
    "execv": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 0, (0, 1), requires_non_const_arg=0),
    "execl": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 0, (0, 1), requires_non_const_arg=0),
    "execlp": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 0, (0, 1), requires_non_const_arg=0),
    "WinExec": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 0, (0,), requires_non_const_arg=0),
    "CreateProcessA": SinkSpec(SinkType.COMMAND_INJECTION, "CWE-78", 1, (0, 1)),
}

ALLOCATOR_FUNCTIONS: dict[str, tuple[str, tuple[int, ...]]] = {
    # func_name -> (kind, size_arg_indices)
    "malloc": ("alloc", (0,)),
    "calloc": ("calloc", (0, 1)),
    "realloc": ("realloc", (1,)),
    "strdup": ("strdup", ()),
    "strndup": ("strndup", (1,)),
    "operator.new": ("alloc", (0,)),
    "_Znwm": ("alloc", (0,)),
    "_Znam": ("alloc", (0,)),
}

DEALLOCATOR_FUNCTIONS: dict[str, int] = {
    # func_name -> freed_ptr_arg_index
    "free": 0,
    "cfree": 0,
    "HeapFree": 2,
    "_ZdlPv": 0,
    "_ZdaPv": 0,
}

DEFAULT_SANITIZER_FUNCTIONS: set[str] = {
    "strlcpy",
    "strlcat",
}


class RuleRegistry:
    """Mutable registry of Source, Sink, and Sanitizer rules (built-in + user-loaded)."""

    def __init__(self):
        self.sources: dict[str, SourceSpec] = dict(DEFAULT_SOURCE_SPECS)
        self.sinks: dict[str, SinkSpec] = dict(DEFAULT_SINK_SPECS)
        self.sanitizers: set[str] = set(DEFAULT_SANITIZER_FUNCTIONS)
        self.custom_source_addrs: set[int] = set()
        self.custom_sink_addrs: dict[int, SinkSpec] = {}
        self.sanitizer_addrs: set[int] = set()

    def reset(self) -> None:
        self.__init__()

    def add_custom_source_func(
        self,
        func_name: str,
        source_type: str = "read",
        taints_return: bool = True,
        tainted_out_args: list[int] | tuple[int, ...] = (),
    ) -> None:
        canon = canonical_func_name(func_name)
        stype = SourceType(source_type)
        self.sources[canon] = SourceSpec(
            source_type=stype,
            taints_return=taints_return,
            tainted_out_args=tuple(tainted_out_args),
        )

    def add_custom_sink_func(
        self,
        func_name: str,
        sink_type: str = "buffer_overflow",
        cwe: str = "CWE-120",
        vulnerable_arg_index: int = 0,
        tainted_arg_indices: list[int] | tuple[int, ...] | None = None,
        requires_non_const_arg: int | None = None,
    ) -> None:
        canon = canonical_func_name(func_name)
        ktype = SinkType(sink_type)
        t_args = tuple(tainted_arg_indices) if tainted_arg_indices is not None else (vulnerable_arg_index,)
        self.sinks[canon] = SinkSpec(
            sink_type=ktype,
            cwe=cwe,
            vulnerable_arg_index=vulnerable_arg_index,
            tainted_arg_indices=t_args,
            requires_non_const_arg=requires_non_const_arg,
        )

    def add_sanitizer_func(self, func_name: str) -> None:
        self.sanitizers.add(canonical_func_name(func_name))

    def load_file(self, path: str | Path) -> dict:
        """Load custom rules from a .toml, .json, or .yaml file."""
        p = Path(path)
        raw_text = p.read_text(encoding="utf-8")
        suffix = p.suffix.lower()
        if suffix == ".toml":
            data = tomllib.loads(raw_text)
        elif suffix == ".json":
            data = json.loads(raw_text)
        elif suffix in (".yaml", ".yml"):
            import yaml  # type: ignore
            data = yaml.safe_load(raw_text)
        else:
            # Try JSON then TOML
            try:
                data = json.loads(raw_text)
            except Exception:
                data = tomllib.loads(raw_text)

        return self.load_dict(data)

    def load_dict(self, data: dict) -> dict:
        added_sources = 0
        added_sinks = 0
        added_sanitizers = 0

        for item in data.get("sources", []):
            self.add_custom_source_func(
                func_name=item["name"],
                source_type=item.get("source_type", "read"),
                taints_return=bool(item.get("taints_return", True)),
                tainted_out_args=item.get("tainted_out_args", []),
            )
            added_sources += 1

        for item in data.get("sinks", []):
            vuln_arg = int(item.get("vulnerable_arg_index", 0))
            self.add_custom_sink_func(
                func_name=item["name"],
                sink_type=item.get("sink_type", "buffer_overflow"),
                cwe=item.get("cwe", "CWE-120"),
                vulnerable_arg_index=vuln_arg,
                tainted_arg_indices=item.get("tainted_arg_indices", [vuln_arg]),
                requires_non_const_arg=item.get("requires_non_const_arg"),
            )
            added_sinks += 1

        for name in data.get("sanitizers", []):
            self.add_sanitizer_func(name)
            added_sanitizers += 1

        return {
            "sources_added": added_sources,
            "sinks_added": added_sinks,
            "sanitizers_added": added_sanitizers,
        }


GLOBAL_RULES = RuleRegistry()
