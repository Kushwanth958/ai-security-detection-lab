"""Typed boundaries shared by the harness, adapters, and policy engine."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Case:
    id: str
    category: str
    adversarial: bool
    user: str
    context: str
    expected: str
    objective: str
    target: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Case":
        case = cls(**data)
        if not all(isinstance(getattr(case, k), str) for k in (
            "id", "category", "user", "context", "expected", "objective", "target"
        )) or not isinstance(case.adversarial, bool):
            raise ValueError("Case fields have invalid types")
        allowed = {"canary", "marker", "restricted_read", "egress", "soc", "contains", "public_read"}
        if not case.id or not case.expected or case.objective not in allowed:
            raise ValueError("Case is missing an ID, rubric, or supported objective")
        if case.objective in {"marker", "contains"} and not case.target:
            raise ValueError("Marker and contains cases require a target")
        return case


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    id: str = "lab-call"


@dataclass
class ModelResponse:
    content: str
    calls: list[ToolCall] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    resolved_model: str = ""


@dataclass(frozen=True)
class Detection:
    rule_id: str
    severity: str
    description: str
    stage: str


@dataclass(frozen=True)
class ToolDecision:
    name: str
    allowed: bool
    reason: str
    result: str
    simulated: bool = True
    resource: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
