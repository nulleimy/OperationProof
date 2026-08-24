from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .canonical import canonical_json_bytes, sha256_digest, valid_digest
from .rfc3339 import parse_rfc3339
from .sdk import ProofAssessment, assess_proof
from .trust import ProviderTrustRegistry

OBSERVABILITY_EVENT_SCHEMA = "operationproof.observability-event.v1"


class ObservabilityEventType(StrEnum):
    PROOF_ASSESSED = "PROOF_ASSESSED"
    ATTESTATION_CREATED = "ATTESTATION_CREATED"
    ATTESTATION_VERIFIED = "ATTESTATION_VERIFIED"
    GATEWAY_ADMISSION_CREATED = "GATEWAY_ADMISSION_CREATED"
    GATEWAY_FORWARD_ALLOWED = "GATEWAY_FORWARD_ALLOWED"
    GATEWAY_FORWARD_COMPLETED = "GATEWAY_FORWARD_COMPLETED"
    GATEWAY_FORWARD_REJECTED = "GATEWAY_FORWARD_REJECTED"
    EXECUTION_RECEIPT_VERIFIED = "EXECUTION_RECEIPT_VERIFIED"
    FINAL_PROOF_VERIFIED = "FINAL_PROOF_VERIFIED"


class ObservabilityError(ValueError):
    """Raised when an observability event cannot be represented canonically."""


class TelemetrySinkError(RuntimeError):
    """Raised by telemetry sinks that cannot accept another event."""


@dataclass(frozen=True, slots=True)
class ObservabilityEmitResult:
    emitted: bool
    reason_codes: tuple[str, ...] = ()


def _snapshot_mapping(value: Mapping[str, Any], code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ObservabilityError(code)
    try:
        encoded = canonical_json_bytes(dict(value))
        decoded = json.loads(encoded.decode("utf-8"))
    except (TypeError, ValueError, OverflowError, RecursionError, json.JSONDecodeError) as exc:
        raise ObservabilityError(code) from exc
    if not isinstance(decoded, dict):
        raise ObservabilityError(code)
    return decoded


def _text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise ObservabilityError(code)
    return value


def _optional_digest(value: str | None, code: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not valid_digest(value):
        raise ObservabilityError(code)
    return value


def observability_event_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(event)
    payload.pop("event_digest", None)
    return payload


def build_observability_event(
    *,
    event_type: ObservabilityEventType | str,
    occurred_at: str,
    operation_id: str,
    subject_digest: str | None = None,
    artifact_digest: str | None = None,
    attestation_digest: str | None = None,
    outcome: str,
    reason_codes: tuple[str, ...] = (),
    attributes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    raw_type = event_type.value if isinstance(event_type, ObservabilityEventType) else event_type
    if raw_type not in {item.value for item in ObservabilityEventType}:
        raise ObservabilityError("INVALID_OBSERVABILITY_EVENT_TYPE")
    try:
        parse_rfc3339(occurred_at)
    except (TypeError, ValueError) as exc:
        raise ObservabilityError("INVALID_OBSERVABILITY_OCCURRED_AT") from exc
    operation = _text(operation_id, "INVALID_OBSERVABILITY_OPERATION_ID")
    outcome_value = _text(outcome, "INVALID_OBSERVABILITY_OUTCOME")
    if not isinstance(reason_codes, tuple) or any(
        not isinstance(code, str) or not code or len(code) > 256 for code in reason_codes
    ):
        raise ObservabilityError("INVALID_OBSERVABILITY_REASON_CODES")
    attributes_snapshot = _snapshot_mapping(attributes or {}, "INVALID_OBSERVABILITY_ATTRIBUTES")
    event: dict[str, Any] = {
        "schema": OBSERVABILITY_EVENT_SCHEMA,
        "event_type": raw_type,
        "occurred_at": occurred_at,
        "operation_id": operation,
        "subject_digest": _optional_digest(
            subject_digest, "INVALID_OBSERVABILITY_SUBJECT_DIGEST"
        ),
        "artifact_digest": _optional_digest(
            artifact_digest, "INVALID_OBSERVABILITY_ARTIFACT_DIGEST"
        ),
        "attestation_digest": _optional_digest(
            attestation_digest, "INVALID_OBSERVABILITY_ATTESTATION_DIGEST"
        ),
        "outcome": outcome_value,
        "reason_codes": list(reason_codes),
        "attributes": attributes_snapshot,
    }
    event["event_digest"] = sha256_digest(event)
    return event


def verify_observability_event(event: Mapping[str, Any]) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    try:
        snapshot = _snapshot_mapping(event, "INVALID_OBSERVABILITY_EVENT")
    except ObservabilityError as exc:
        return False, (str(exc),)
    if snapshot.get("schema") != OBSERVABILITY_EVENT_SCHEMA:
        reasons.append("UNSUPPORTED_OBSERVABILITY_EVENT_SCHEMA")
    if snapshot.get("event_type") not in {item.value for item in ObservabilityEventType}:
        reasons.append("INVALID_OBSERVABILITY_EVENT_TYPE")
    try:
        parse_rfc3339(snapshot.get("occurred_at"))
    except (TypeError, ValueError):
        reasons.append("INVALID_OBSERVABILITY_OCCURRED_AT")
    for field_name in ("operation_id", "outcome"):
        value = snapshot.get(field_name)
        if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
            reasons.append(f"INVALID_OBSERVABILITY_FIELD:{field_name}")
    for field_name in ("subject_digest", "artifact_digest", "attestation_digest"):
        value = snapshot.get(field_name)
        if value is not None and (not isinstance(value, str) or not valid_digest(value)):
            reasons.append(f"INVALID_OBSERVABILITY_DIGEST:{field_name}")
    reason_codes = snapshot.get("reason_codes")
    if not isinstance(reason_codes, list) or any(
        not isinstance(code, str) or not code or len(code) > 256 for code in reason_codes
    ):
        reasons.append("INVALID_OBSERVABILITY_REASON_CODES")
    if not isinstance(snapshot.get("attributes"), Mapping):
        reasons.append("INVALID_OBSERVABILITY_ATTRIBUTES")
    supplied = snapshot.get("event_digest")
    if not isinstance(supplied, str) or not valid_digest(supplied):
        reasons.append("INVALID_OBSERVABILITY_EVENT_DIGEST")
    elif sha256_digest(observability_event_payload(snapshot)) != supplied:
        reasons.append("OBSERVABILITY_EVENT_DIGEST_MISMATCH")
    return not reasons, tuple(sorted(set(reasons)))


class TelemetrySink:
    def emit(self, event: Mapping[str, Any]) -> None:
        raise NotImplementedError


class MemoryTelemetrySink(TelemetrySink):
    def __init__(self, *, max_events: int = 10_000) -> None:
        if not isinstance(max_events, int) or isinstance(max_events, bool) or max_events <= 0:
            raise TelemetrySinkError("INVALID_TELEMETRY_CAPACITY")
        self._max_events = max_events
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def emit(self, event: Mapping[str, Any]) -> None:
        valid, reasons = verify_observability_event(event)
        if not valid:
            raise TelemetrySinkError("INVALID_OBSERVABILITY_EVENT:" + ",".join(reasons))
        snapshot = _snapshot_mapping(event, "INVALID_OBSERVABILITY_EVENT")
        with self._lock:
            if len(self._events) >= self._max_events:
                raise TelemetrySinkError("TELEMETRY_CAPACITY_EXHAUSTED")
            self._events.append(snapshot)

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(_snapshot_mapping(item, "INVALID_OBSERVABILITY_EVENT") for item in self._events)


def emit_observability_event(
    sink: TelemetrySink | None,
    event: Mapping[str, Any],
) -> ObservabilityEmitResult:
    """Best-effort telemetry boundary that never mutates governance semantics."""

    valid, reasons = verify_observability_event(event)
    if not valid:
        return ObservabilityEmitResult(False, tuple(f"EVENT:{code}" for code in reasons))
    if sink is None:
        return ObservabilityEmitResult(False, ("TELEMETRY_SINK_NOT_CONFIGURED",))
    if not isinstance(sink, TelemetrySink):
        return ObservabilityEmitResult(False, ("INVALID_TELEMETRY_SINK",))
    try:
        sink.emit(_snapshot_mapping(event, "INVALID_OBSERVABILITY_EVENT"))
    except Exception:
        return ObservabilityEmitResult(False, ("TELEMETRY_SINK_FAILED",))
    return ObservabilityEmitResult(True, ())


def assess_proof_observed(
    proof: Mapping[str, Any],
    *,
    registry: ProviderTrustRegistry | None,
    sink: TelemetrySink | None,
    occurred_at: str,
) -> tuple[ProofAssessment, ObservabilityEmitResult]:
    """Assess a proof and emit telemetry without allowing sink state to affect acceptance."""

    assessment = assess_proof(proof, registry=registry)
    operation_id = assessment.operation_id or "unknown-operation"
    subject_digest = proof.get("subject_digest") if isinstance(proof, Mapping) else None
    if not isinstance(subject_digest, str) or not valid_digest(subject_digest):
        subject_digest = None
    proof_digest = proof.get("proof_digest") if isinstance(proof, Mapping) else None
    if not isinstance(proof_digest, str) or not valid_digest(proof_digest):
        proof_digest = None
    event = build_observability_event(
        event_type=ObservabilityEventType.PROOF_ASSESSED,
        occurred_at=occurred_at,
        operation_id=operation_id,
        subject_digest=subject_digest,
        artifact_digest=proof_digest,
        outcome="ACCEPTED" if assessment.accepted else "REJECTED",
        reason_codes=assessment.reason_codes,
        attributes={
            "schema": assessment.schema,
            "phase": assessment.phase,
            "integrity_valid": assessment.integrity_valid,
            "trust_evaluated": assessment.trust_evaluated,
            "trusted": assessment.trusted,
            "decision": assessment.decision,
        },
    )
    return assessment, emit_observability_event(sink, event)
