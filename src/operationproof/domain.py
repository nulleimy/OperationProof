from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Layer(StrEnum):
    IDENTITY = "identity"
    AUTHORIZATION = "authorization"
    INTENT = "intent"
    CONTINUITY = "continuity"
    TOOL_SAFETY = "tool_safety"
    DATA_FLOW = "data_flow"
    RESOURCE = "resource"
    EXECUTION = "execution"


PRE_LAYERS: tuple[Layer, ...] = (
    Layer.IDENTITY,
    Layer.AUTHORIZATION,
    Layer.INTENT,
    Layer.CONTINUITY,
    Layer.TOOL_SAFETY,
    Layer.DATA_FLOW,
    Layer.RESOURCE,
)


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ProofDecision(StrEnum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class EvidenceEnvelope:
    layer: Layer
    provider: str
    operation_id: str
    decision: str
    verdict: Verdict
    subject_digest: str
    evidence_digest: str
    issued_at: str
    expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    schema: str = "operationproof.evidence-envelope.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "layer": self.layer.value,
            "provider": self.provider,
            "operation_id": self.operation_id,
            "decision": self.decision,
            "verdict": self.verdict.value,
            "subject_digest": self.subject_digest,
            "evidence_digest": self.evidence_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "metadata": self.metadata,
        }
