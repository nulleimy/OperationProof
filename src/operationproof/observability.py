from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from .canonical import sha256_digest, valid_digest
from .rfc3339 import parse_rfc3339

OBSERVABILITY_EVENT_CONTRACT = "operationproof.observability-event.v1"
OBSERVABILITY_EVENT_TYPES = frozenset(
    {
        "proof_assessed",
        "admission_created",
        "admission_consumed",
        "upstream_dispatch_prepared",
        "upstream_dispatched",
        "upstream_completed",
        "upstream_failed",
        "execution_receipt_verified",
        "final_proof_composed",
    }
)


class TelemetrySink(ABC):
    """Best-effort metrics/log export boundary; never provenance evidence by itself."""

    @abstractmethod
    def emit(self, event: Mapping[str, Any]) -> None:
        """Export one structured event."""


class MemoryTelemetrySink(TelemetrySink):
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def emit(self, event: Mapping[str, Any]) -> None:
        with self._lock:
            self._events.append(dict(event))

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(item) for item in self._events)


def build_observability_event(
    *,
    event_id: str,
    event_type: str,
    operation_id: str,
    subject_digest: str,
    proof_digest: str,
    artifact_digest: str,
    occurred_at: str,
    state_from: str | None = None,
    state_to: str | None = None,
    reason_codes: tuple[str, ...] = (),
) -> dict[str, Any]:
    for field, value in (("event_id", event_id), ("operation_id", operation_id)):
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or "\x00" in value
            or len(value) > 512
        ):
            raise ValueError(f"INVALID_OBSERVABILITY_FIELD:{field}")
    if event_type not in OBSERVABILITY_EVENT_TYPES:
        raise ValueError("INVALID_OBSERVABILITY_EVENT_TYPE")
    for field, value in (
        ("subject_digest", subject_digest),
        ("proof_digest", proof_digest),
        ("artifact_digest", artifact_digest),
    ):
        if not isinstance(value, str) or not valid_digest(value):
            raise ValueError(f"INVALID_OBSERVABILITY_DIGEST:{field}")
    try:
        parse_rfc3339(occurred_at)
    except (TypeError, ValueError) as exc:
        raise ValueError("INVALID_OBSERVABILITY_OCCURRED_AT") from exc
    for field, value in (("state_from", state_from), ("state_to", state_to)):
        if value is not None and (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or "\x00" in value
            or len(value) > 128
        ):
            raise ValueError(f"INVALID_OBSERVABILITY_FIELD:{field}")
    if not isinstance(reason_codes, tuple) or any(
        not isinstance(code, str)
        or not code
        or code != code.strip()
        or "\x00" in code
        or len(code) > 256
        for code in reason_codes
    ):
        raise ValueError("INVALID_OBSERVABILITY_REASON_CODES")

    payload: dict[str, Any] = {
        "schema": OBSERVABILITY_EVENT_CONTRACT,
        "event_id": event_id,
        "event_type": event_type,
        "operation_id": operation_id,
        "subject_digest": subject_digest,
        "proof_digest": proof_digest,
        "artifact_digest": artifact_digest,
        "occurred_at": occurred_at,
        "state_from": state_from,
        "state_to": state_to,
        "reason_codes": sorted(set(reason_codes)),
    }
    payload["event_digest"] = sha256_digest(payload)
    return payload


def emit_telemetry_best_effort(
    sink: TelemetrySink | None,
    event: Mapping[str, Any],
) -> bool:
    if sink is None:
        return False
    try:
        sink.emit(dict(event))
    except Exception:
        return False
    return True
