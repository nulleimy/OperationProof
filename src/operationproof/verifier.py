from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .canonical import proof_payload, sha256_digest, valid_digest
from .domain import Layer, PRE_LAYERS, ProofDecision


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    reason_codes: tuple[str, ...]


def _parse_time(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def evaluate_evidence_set(
    *,
    operation_id: str,
    evidence: list[dict[str, Any]],
    required_layers: set[str],
    forbidden_layers: set[str] | None = None,
    now: datetime | None = None,
) -> tuple[ProofDecision, list[str]]:
    reasons: list[str] = []
    seen: set[str] = set()
    forbidden_layers = forbidden_layers or set()
    now = now or datetime.now(timezone.utc)

    for item in evidence:
        layer = item.get("layer")
        if layer in seen:
            reasons.append(f"DUPLICATE_LAYER:{layer}")
        seen.add(layer)

        if layer in forbidden_layers:
            reasons.append(f"FORBIDDEN_LAYER:{layer}")
        if item.get("operation_id") != operation_id:
            reasons.append(f"OPERATION_ID_MISMATCH:{layer}")
        if item.get("verdict") == "FAIL":
            reasons.append(f"LAYER_FAIL:{layer}")
        elif item.get("verdict") != "PASS":
            reasons.append(f"LAYER_UNKNOWN:{layer}")

        for digest_field in ("subject_digest", "evidence_digest"):
            if not valid_digest(str(item.get(digest_field, ""))):
                reasons.append(f"INVALID_DIGEST:{layer}:{digest_field}")

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


def verify_proof(proof: dict[str, Any]) -> VerificationResult:
    reasons: list[str] = []
    supplied_digest = proof.get("proof_digest")
    if not valid_digest(str(supplied_digest or "")):
        reasons.append("INVALID_PROOF_DIGEST_FORMAT")
    elif sha256_digest(proof_payload(proof)) != supplied_digest:
        reasons.append("PROOF_DIGEST_MISMATCH")

    if proof.get("schema") != "operationproof.operation-proof.v1":
        reasons.append("UNSUPPORTED_SCHEMA")

    phase = proof.get("phase")
    operation_id = proof.get("operation_id")
    if not isinstance(operation_id, str) or not operation_id:
        reasons.append("INVALID_OPERATION_ID")

    evidence = proof.get("evidence")
    if not isinstance(evidence, list):
        reasons.append("INVALID_EVIDENCE")
        evidence = []

    if phase == "PRE" and isinstance(operation_id, str):
        decision, evidence_reasons = evaluate_evidence_set(
            operation_id=operation_id,
            evidence=evidence,
            required_layers={layer.value for layer in PRE_LAYERS},
            forbidden_layers={Layer.EXECUTION.value},
        )
        reasons.extend(evidence_reasons)
        expected_decision = decision.value
    elif phase == "FINAL" and isinstance(operation_id, str):
        pre_digest = proof.get("pre_proof_digest")
        if not valid_digest(str(pre_digest or "")):
            reasons.append("INVALID_PRE_PROOF_DIGEST")
        decision, evidence_reasons = evaluate_evidence_set(
            operation_id=operation_id,
            evidence=evidence,
            required_layers={Layer.EXECUTION.value},
        )
        reasons.extend(evidence_reasons)
        unexpected = {item.get("layer") for item in evidence} - {Layer.EXECUTION.value}
        for layer in sorted(str(value) for value in unexpected):
            reasons.append(f"UNEXPECTED_FINAL_LAYER:{layer}")
        expected_decision = decision.value
    else:
        reasons.append("INVALID_PHASE")
        expected_decision = ProofDecision.REJECTED.value

    if proof.get("decision") != expected_decision:
        reasons.append("DECISION_MISMATCH")

    recorded_reasons = proof.get("reason_codes")
    if not isinstance(recorded_reasons, list):
        reasons.append("INVALID_REASON_CODES")

    return VerificationResult(valid=not reasons, reason_codes=tuple(sorted(set(reasons))))
