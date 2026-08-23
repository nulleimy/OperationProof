from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .canonical import proof_payload, sha256_digest, valid_digest
from .domain import PRE_LAYERS, Layer, ProofDecision

_PROOF_FIELDS = frozenset(
    {
        "schema",
        "phase",
        "operation_id",
        "decision",
        "reason_codes",
        "pre_proof_digest",
        "pre_proof",
        "evidence",
        "proof_digest",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "layer",
        "provider",
        "operation_id",
        "decision",
        "verdict",
        "subject_digest",
        "evidence_digest",
        "issued_at",
        "expires_at",
        "metadata",
    }
)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    reason_codes: tuple[str, ...]


def _parse_time(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def _unexpected_evidence_fields(item: dict[str, Any], *, index: int) -> str | None:
    unexpected_fields = sorted(set(item) - _EVIDENCE_FIELDS)
    if not unexpected_fields:
        return None
    layer = item.get("layer")
    layer_name = layer if isinstance(layer, str) and layer else f"<invalid:{index}>"
    return f"UNEXPECTED_EVIDENCE_FIELDS:{layer_name}:" + ",".join(unexpected_fields)


def _validate_evidence_envelope(
    item: Any,
    *,
    index: int,
    now: datetime,
) -> tuple[str | None, list[str]]:
    if not isinstance(item, dict):
        return None, [f"INVALID_EVIDENCE_ENTRY:{index}"]

    reasons: list[str] = []
    layer = item.get("layer")
    layer_name = layer if isinstance(layer, str) and layer else f"<invalid:{index}>"

    unexpected_reason = _unexpected_evidence_fields(item, index=index)
    if unexpected_reason is not None:
        reasons.append(unexpected_reason)

    if item.get("schema") != "operationproof.evidence-envelope.v1":
        reasons.append(f"UNSUPPORTED_EVIDENCE_SCHEMA:{layer_name}")
    if not isinstance(layer, str) or not layer:
        reasons.append(f"INVALID_LAYER:{index}")
        layer = None
    if not isinstance(item.get("provider"), str) or not item.get("provider"):
        reasons.append(f"INVALID_PROVIDER:{layer_name}")
    if not isinstance(item.get("operation_id"), str) or not item.get("operation_id"):
        reasons.append(f"INVALID_EVIDENCE_OPERATION_ID:{layer_name}")
    if not isinstance(item.get("decision"), str) or not item.get("decision"):
        reasons.append(f"INVALID_NATIVE_DECISION:{layer_name}")
    if item.get("verdict") not in {"PASS", "FAIL", "UNKNOWN"}:
        reasons.append(f"INVALID_VERDICT:{layer_name}")

    for digest_field in ("subject_digest", "evidence_digest"):
        if not valid_digest(str(item.get(digest_field, ""))):
            reasons.append(f"INVALID_DIGEST:{layer_name}:{digest_field}")

    issued_at = item.get("issued_at")
    issued_time: datetime | None = None
    if not isinstance(issued_at, str) or not issued_at:
        reasons.append(f"INVALID_ISSUED_AT:{layer_name}")
    else:
        try:
            issued_time = _parse_time(issued_at)
        except (TypeError, ValueError):
            reasons.append(f"INVALID_ISSUED_AT:{layer_name}")

    expires_at = item.get("expires_at")
    if expires_at is not None:
        if not isinstance(expires_at, str) or not expires_at:
            reasons.append(f"INVALID_EXPIRY:{layer_name}")
        else:
            try:
                expiry_time = _parse_time(expires_at)
                if expiry_time <= now:
                    reasons.append(f"EXPIRED_EVIDENCE:{layer_name}")
                if issued_time is not None and expiry_time <= issued_time:
                    reasons.append(f"INVALID_EXPIRY_ORDER:{layer_name}")
            except (TypeError, ValueError):
                reasons.append(f"INVALID_EXPIRY:{layer_name}")

    if not isinstance(item.get("metadata"), dict):
        reasons.append(f"INVALID_METADATA:{layer_name}")

    return layer, reasons


def evaluate_evidence_set(
    *,
    operation_id: str,
    evidence: list[Any],
    required_layers: set[str],
    forbidden_layers: set[str] | None = None,
    allowed_layers: set[str] | None = None,
    now: datetime | None = None,
) -> tuple[ProofDecision, list[str]]:
    reasons: list[str] = []
    seen: set[str] = set()
    forbidden_layers = forbidden_layers or set()
    now = now or datetime.now(UTC)

    for index, item in enumerate(evidence):
        layer, envelope_reasons = _validate_evidence_envelope(item, index=index, now=now)
        reasons.extend(envelope_reasons)
        if not isinstance(item, dict) or layer is None:
            continue

        if layer in seen:
            reasons.append(f"DUPLICATE_LAYER:{layer}")
        seen.add(layer)

        if layer in forbidden_layers:
            reasons.append(f"FORBIDDEN_LAYER:{layer}")
        if allowed_layers is not None and layer not in allowed_layers:
            reasons.append(f"UNEXPECTED_LAYER:{layer}")
        if item.get("operation_id") != operation_id:
            reasons.append(f"OPERATION_ID_MISMATCH:{layer}")
        if item.get("verdict") == "FAIL":
            reasons.append(f"LAYER_FAIL:{layer}")
        elif item.get("verdict") != "PASS":
            reasons.append(f"LAYER_UNKNOWN:{layer}")

    for missing in sorted(required_layers - seen):
        reasons.append(f"MISSING_LAYER:{missing}")

    decision = ProofDecision.VERIFIED if not reasons else ProofDecision.REJECTED
    return decision, sorted(set(reasons))


def evaluate_pre_semantics(
    operation_id: str,
    evidence: list[Any],
) -> tuple[ProofDecision, list[str]]:
    return evaluate_evidence_set(
        operation_id=operation_id,
        evidence=evidence,
        required_layers={layer.value for layer in PRE_LAYERS},
        forbidden_layers={Layer.EXECUTION.value},
        allowed_layers={layer.value for layer in PRE_LAYERS},
    )


def evaluate_final_semantics(
    *,
    operation_id: Any,
    pre_proof: Any,
    pre_digest: Any,
    evidence: list[Any],
) -> tuple[ProofDecision, list[str]]:
    reasons: list[str] = []

    if not isinstance(operation_id, str) or not operation_id:
        reasons.append("INVALID_OPERATION_ID")

    if not isinstance(pre_proof, dict):
        reasons.append("PRE_PROOF_MISSING")
    else:
        pre_result = verify_proof(pre_proof)
        if not pre_result.valid:
            reasons.append("PRE_PROOF_INVALID")
        if pre_proof.get("phase") != "PRE":
            reasons.append("PRE_PROOF_PHASE_INVALID")
        if pre_proof.get("decision") != ProofDecision.VERIFIED.value:
            reasons.append("PRE_PROOF_NOT_VERIFIED")
        if pre_proof.get("operation_id") != operation_id:
            reasons.append("PRE_PROOF_OPERATION_ID_MISMATCH")
        if pre_proof.get("proof_digest") != pre_digest:
            reasons.append("PRE_PROOF_DIGEST_MISMATCH")

    if not valid_digest(str(pre_digest or "")):
        reasons.append("INVALID_PRE_PROOF_DIGEST")

    if isinstance(operation_id, str):
        _, execution_reasons = evaluate_evidence_set(
            operation_id=operation_id,
            evidence=evidence,
            required_layers={Layer.EXECUTION.value},
            allowed_layers={Layer.EXECUTION.value},
        )
        reasons.extend(execution_reasons)

    reasons = sorted(set(reasons))
    decision = ProofDecision.VERIFIED if not reasons else ProofDecision.REJECTED
    return decision, reasons


def _record_matches(
    proof: dict[str, Any],
    expected_decision: str,
    reasons: list[str],
) -> list[str]:
    integrity: list[str] = []
    if proof.get("decision") != expected_decision:
        integrity.append("DECISION_MISMATCH")
    recorded_reasons = proof.get("reason_codes")
    if not isinstance(recorded_reasons, list):
        integrity.append("INVALID_REASON_CODES")
    elif recorded_reasons != sorted(set(reasons)):
        integrity.append("REASON_CODES_MISMATCH")
    return integrity


def verify_proof(proof: dict[str, Any]) -> VerificationResult:
    integrity: list[str] = []

    unexpected_fields = sorted(set(proof) - _PROOF_FIELDS)
    if unexpected_fields:
        integrity.append("UNEXPECTED_PROOF_FIELDS:" + ",".join(unexpected_fields))

    supplied_digest = proof.get("proof_digest")
    if not valid_digest(str(supplied_digest or "")):
        integrity.append("INVALID_PROOF_DIGEST_FORMAT")
    elif sha256_digest(proof_payload(proof)) != supplied_digest:
        integrity.append("PROOF_DIGEST_MISMATCH")

    if proof.get("schema") != "operationproof.operation-proof.v1":
        integrity.append("UNSUPPORTED_SCHEMA")

    phase = proof.get("phase")
    operation_id = proof.get("operation_id")
    if not isinstance(operation_id, str) or not operation_id:
        integrity.append("INVALID_OPERATION_ID")

    evidence = proof.get("evidence")
    if not isinstance(evidence, list):
        integrity.append("INVALID_EVIDENCE")
        evidence = []
    else:
        for index, item in enumerate(evidence):
            if isinstance(item, dict):
                unexpected_reason = _unexpected_evidence_fields(item, index=index)
                if unexpected_reason is not None:
                    integrity.append(unexpected_reason)

    semantic_reasons: list[str] = []
    if phase == "PRE" and isinstance(operation_id, str):
        if "pre_proof" in proof:
            integrity.append("PRE_PROOF_FIELD_FORBIDDEN")
        if "pre_proof_digest" in proof:
            integrity.append("PRE_PROOF_DIGEST_FIELD_FORBIDDEN")
        decision, semantic_reasons = evaluate_pre_semantics(operation_id, evidence)
        expected_decision = decision.value
    elif phase == "FINAL":
        decision, semantic_reasons = evaluate_final_semantics(
            operation_id=operation_id,
            pre_proof=proof.get("pre_proof"),
            pre_digest=proof.get("pre_proof_digest"),
            evidence=evidence,
        )
        expected_decision = decision.value
    else:
        integrity.append("INVALID_PHASE")
        expected_decision = ProofDecision.REJECTED.value

    integrity.extend(_record_matches(proof, expected_decision, semantic_reasons))
    return VerificationResult(
        valid=not integrity,
        reason_codes=tuple(sorted(set(integrity))),
    )
