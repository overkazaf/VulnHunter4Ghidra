from dataclasses import dataclass, field
from enum import Enum


class SourceType(Enum):
    FUNC_PARAM = "func_param"
    ARGV = "argv"
    STDIN = "stdin"
    RECV = "recv"
    READ = "read"
    FGETS = "fgets"
    SCANF = "scanf"
    ENV = "env"
    FILE_READ = "file_read"


class SinkType(Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    COMMAND_INJECTION = "command_injection"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_DEREF = "null_deref"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Source:
    address: int
    func_addr: int
    func_name: str
    source_type: SourceType
    description: str
    param_index: int | None = None

    def to_dict(self) -> dict:
        d = {
            "address": hex(self.address),
            "func_addr": hex(self.func_addr),
            "func_name": self.func_name,
            "source_type": self.source_type.value,
            "description": self.description,
        }
        if self.param_index is not None:
            d["param_index"] = self.param_index
        return d


@dataclass
class Sink:
    address: int
    func_addr: int
    func_name: str
    callee_name: str
    sink_type: SinkType
    cwe: str
    vulnerable_arg_index: int

    def to_dict(self) -> dict:
        return {
            "address": hex(self.address),
            "func_addr": hex(self.func_addr),
            "func_name": self.func_name,
            "callee_name": self.callee_name,
            "sink_type": self.sink_type.value,
            "cwe": self.cwe,
            "vulnerable_arg_index": self.vulnerable_arg_index,
        }


@dataclass
class TaintPath:
    source: Source
    sink: Sink
    path_addrs: list[int]
    path_funcs: list[str]

    def to_dict(self) -> dict:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "path_addrs": [hex(a) for a in self.path_addrs],
            "path_funcs": self.path_funcs,
            "path_length": len(self.path_addrs),
        }


CWE_SEVERITY: dict[str, Severity] = {
    "CWE-119": Severity.CRITICAL,
    "CWE-120": Severity.CRITICAL,
    "CWE-121": Severity.CRITICAL,
    "CWE-122": Severity.CRITICAL,
    "CWE-124": Severity.HIGH,
    "CWE-125": Severity.HIGH,
    "CWE-126": Severity.HIGH,
    "CWE-127": Severity.HIGH,
    "CWE-134": Severity.CRITICAL,
    "CWE-190": Severity.HIGH,
    "CWE-415": Severity.CRITICAL,
    "CWE-416": Severity.CRITICAL,
    "CWE-476": Severity.MEDIUM,
    "CWE-676": Severity.MEDIUM,
    "CWE-787": Severity.CRITICAL,
    "CWE-78": Severity.CRITICAL,
}


@dataclass
class VulnFinding:
    finding_id: int
    taint_path: TaintPath
    cwe: str
    severity: Severity
    title: str
    description: str
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "taint_path": self.taint_path.to_dict(),
            "cwe": self.cwe,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "verified": self.verified,
        }


def classify_severity(cwe: str) -> Severity:
    return CWE_SEVERITY.get(cwe, Severity.MEDIUM)
