from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import sha256_digest, valid_digest

_SUBJECT_SCHEMA = "operationproof.operation-subject.v1"
_SUBJECT_FIELDS = frozenset(
    {
        "schema",
        "operation_id",
        "actor_digest",
        "intent_digest",
        "target_digest",
        "state_digest",
    }
)


class OperationSubjectError(ValueError):
    """Raised when a canonical OperationSubject is malformed."""


def _require_text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise OperationSubjectError(code)
    return value


def _require_digest(value: object, code: str) -> str:
    text = _require_text(value, code)
    if not valid_digest(text):
        raise OperationSubjectError(code)
    return text


@dataclass(frozen=True, slots=True)
class OperationSubject:
    """Provider-neutral identity of the exact operation being evidenced.

    Each component is an opaque canonical digest. Providers may use different native
    identity vocabularies, but evidence can compose only after those vocabularies are
    mapped to these same four dimensions and therefore to the same subject digest.
    """

    operation_id: str
    actor_digest: str
    intent_digest: str
    target_digest: str
    state_digest: str
    schema: str = _SUBJECT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != _SUBJECT_SCHEMA:
            raise OperationSubjectError("UNSUPPORTED_OPERATION_SUBJECT_SCHEMA")
        _require_text(self.operation_id, "INVALID_OPERATION_SUBJECT_OPERATION_ID")
        _require_digest(self.actor_digest, "INVALID_OPERATION_SUBJECT_ACTOR_DIGEST")
        _require_digest(self.intent_digest, "INVALID_OPERATION_SUBJECT_INTENT_DIGEST")
        _require_digest(self.target_digest, "INVALID_OPERATION_SUBJECT_TARGET_DIGEST")
        _require_digest(self.state_digest, "INVALID_OPERATION_SUBJECT_STATE_DIGEST")

    def to_dict(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "operation_id": self.operation_id,
            "actor_digest": self.actor_digest,
            "intent_digest": self.intent_digest,
            "target_digest": self.target_digest,
            "state_digest": self.state_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> OperationSubject:
        if not isinstance(value, Mapping):
            raise OperationSubjectError("INVALID_OPERATION_SUBJECT")
        if set(value) != _SUBJECT_FIELDS:
            raise OperationSubjectError("INVALID_OPERATION_SUBJECT_FIELDS")
        return cls(
            schema=_require_text(value.get("schema"), "INVALID_OPERATION_SUBJECT_SCHEMA"),
            operation_id=_require_text(
                value.get("operation_id"),
                "INVALID_OPERATION_SUBJECT_OPERATION_ID",
            ),
            actor_digest=_require_digest(
                value.get("actor_digest"),
                "INVALID_OPERATION_SUBJECT_ACTOR_DIGEST",
            ),
            intent_digest=_require_digest(
                value.get("intent_digest"),
                "INVALID_OPERATION_SUBJECT_INTENT_DIGEST",
            ),
            target_digest=_require_digest(
                value.get("target_digest"),
                "INVALID_OPERATION_SUBJECT_TARGET_DIGEST",
            ),
            state_digest=_require_digest(
                value.get("state_digest"),
                "INVALID_OPERATION_SUBJECT_STATE_DIGEST",
            ),
        )
