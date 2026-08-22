from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .canonical import proof_payload, sha256_digest, valid_digest
from .domain import PRE_LAYERS, Layer, ProofDecision


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


def evaluate_evidence_set(
    *,
    operation_id: str,
    evidence: list[dict[str, Any]],
    required_layers: set[str],
    forbidden_layers: set[str] | None = None,
    allowed_layers: set[str] | None = None,
    now: datetime | None = None,
) -> tuple[ProofDecision, list[str]]:
    reasons: list[str] = []
    seen: set[str] = set()
    forbidden_layers = forbidden_layers or set()
    now = now or datetime.now(UTC)

    for item in evidence:
        layer = item.get("layer")
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

        for digest_field in ("subject_digest", "evidence_digest"):
            if not valid_digest(str(item.get(digest_field, ""))):
                reasons.append(f"INVALID_DIGEST:{layer}:{digest_field}")

        issued_at = item.get("issued_at")
        try:
            _parse_time(str(issued_at))
        except (TypeError, ValueError):
            reasons.append(f"INVALID_ISSUED_AT:{layer}")

        expires_at = item.get("expires_at")
        if expires_at:
            try:
                if _parse_time(expires_at) <= now:
                    reasons.append(f"EXPIRED_EVIDENCE:{layer}")
            except (TypeError, ValueError):
                reasons.append(f"INVALID_EXPIRY:{layer}")

    for missing in sorted(required_layers - seen):
        reasons.append(f"MISSING_LAYER:{missing}")

    decision = ProofDecision.VERIFIED if not reasons else ProofDecision.REJECTED
    return decision, sorted(set(reasons))


def evaluate_pre_semantics(
    operation_id: str,
    evidence: list[dict[str, Any]],
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
    evidence: list[dict[str, Any]],
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

    semantic_reasons: list[str] = []
    if phase == "PRE" and isinstance(operation_id, str):
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
