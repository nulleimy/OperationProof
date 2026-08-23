from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json_bytes
from .domain import ProofDecision
from .trust import ProviderTrustRegistry, verify_proof_trust
from .verifier import verify_proof

SDK_CONTRACT = "operationproof.sdk.v1"


class ProofDocumentError(ValueError):
    """Raised when raw proof JSON cannot be represented as one unambiguous document."""


def _reject_json_constant(value: str) -> None:
    raise ProofDocumentError(f"NON_FINITE_JSON_NUMBER:{value}")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofDocumentError(f"DUPLICATE_JSON_KEY:{key}")
        result[key] = value
    return result


def parse_proof_json(data: str | bytes | bytearray) -> dict[str, Any]:
    """Parse one proof JSON document without duplicate-key or NaN ambiguity."""

    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProofDocumentError("INVALID_PROOF_UTF8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise ProofDocumentError("INVALID_PROOF_JSON_INPUT")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except ProofDocumentError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ProofDocumentError("INVALID_PROOF_JSON") from exc

    if not isinstance(parsed, dict):
        raise ProofDocumentError("PROOF_DOCUMENT_MUST_BE_OBJECT")
    return parsed


def canonical_proof_json(proof: Mapping[str, Any]) -> str:
    """Serialize a proof mapping with the same canonical JSON rules used by digests."""

    if not isinstance(proof, Mapping):
        raise ProofDocumentError("PROOF_DOCUMENT_MUST_BE_OBJECT")
    try:
        return canonical_json_bytes(dict(proof)).decode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProofDocumentError("INVALID_PROOF_DOCUMENT") from exc


@dataclass(frozen=True, slots=True)
class ProofAssessment:
    """Safe SDK result separating integrity, semantic decision, and provider trust."""

    schema: str | None
    phase: str | None
    operation_id: str | None
    integrity_valid: bool
    decision: str | None
    trust_evaluated: bool
    trusted: bool | None
    accepted: bool
    integrity_reason_codes: tuple[str, ...] = ()
    trust_reason_codes: tuple[str, ...] = ()
    sdk_reason_codes: tuple[str, ...] = ()
    contract: str = SDK_CONTRACT

    @property
    def reason_codes(self) -> tuple[str, ...]:
        values = [f"INTEGRITY:{code}" for code in self.integrity_reason_codes]
        values.extend(f"TRUST:{code}" for code in self.trust_reason_codes)
        values.extend(f"SDK:{code}" for code in self.sdk_reason_codes)
        return tuple(values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "schema": self.schema,
            "phase": self.phase,
            "operation_id": self.operation_id,
            "integrity_valid": self.integrity_valid,
            "decision": self.decision,
            "trust_evaluated": self.trust_evaluated,
            "trusted": self.trusted,
            "accepted": self.accepted,
            "integrity_reason_codes": list(self.integrity_reason_codes),
            "trust_reason_codes": list(self.trust_reason_codes),
            "sdk_reason_codes": list(self.sdk_reason_codes),
            "reason_codes": list(self.reason_codes),
        }


def _field(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _invalid_assessment(code: str) -> ProofAssessment:
    return ProofAssessment(
        schema=None,
        phase=None,
        operation_id=None,
        integrity_valid=False,
        decision=None,
        trust_evaluated=False,
        trusted=None,
        accepted=False,
        sdk_reason_codes=(code,),
    )


def _snapshot_proof(proof: Mapping[str, Any]) -> dict[str, Any]:
    try:
        payload = canonical_json_bytes(dict(proof))
        snapshot = json.loads(payload.decode("utf-8"))
    except (TypeError, ValueError, OverflowError, json.JSONDecodeError) as exc:
        raise ProofDocumentError("INVALID_PROOF_DOCUMENT") from exc
    if not isinstance(snapshot, dict):
        raise ProofDocumentError("PROOF_DOCUMENT_MUST_BE_OBJECT")
    return snapshot


def assess_proof(
    proof: Mapping[str, Any],
    *,
    registry: ProviderTrustRegistry | None = None,
) -> ProofAssessment:
    """Assess one proof without conflating integrity with governed acceptance.

    ``accepted`` is deliberately fail-closed. It becomes true only when the proof is
    integrity-valid, records semantic ``VERIFIED``, and provider trust has actually
    been evaluated with the supplied registry and returned trusted.
    """

    if not isinstance(proof, Mapping):
        return _invalid_assessment("PROOF_DOCUMENT_MUST_BE_OBJECT")
    try:
        snapshot = _snapshot_proof(proof)
    except ProofDocumentError as exc:
        return _invalid_assessment(str(exc))

    integrity = verify_proof(snapshot)
    decision = _field(snapshot.get("decision"))
    schema = _field(snapshot.get("schema"))
    phase = _field(snapshot.get("phase"))
    operation_id = _field(snapshot.get("operation_id"))

    trust_evaluated = False
    trusted: bool | None = None
    trust_reasons: tuple[str, ...] = ()
    sdk_reasons: tuple[str, ...] = ()

    if registry is None:
        sdk_reasons = ("TRUST_NOT_EVALUATED",)
    elif not isinstance(registry, ProviderTrustRegistry):
        sdk_reasons = ("INVALID_TRUST_REGISTRY",)
    else:
        trust_evaluated = True
        trust_snapshot = _snapshot_proof(snapshot)
        trust_result = verify_proof_trust(trust_snapshot, registry)
        trusted = trust_result.trusted
        trust_reasons = trust_result.reason_codes

    accepted = bool(
        integrity.valid
        and decision == ProofDecision.VERIFIED.value
        and trust_evaluated
        and trusted is True
    )

    return ProofAssessment(
        schema=schema,
        phase=phase,
        operation_id=operation_id,
        integrity_valid=integrity.valid,
        decision=decision,
        trust_evaluated=trust_evaluated,
        trusted=trusted,
        accepted=accepted,
        integrity_reason_codes=integrity.reason_codes,
        trust_reason_codes=trust_reasons,
        sdk_reason_codes=sdk_reasons,
    )


def assess_proof_json(
    data: str | bytes | bytearray,
    *,
    registry: ProviderTrustRegistry | None = None,
) -> ProofAssessment:
    """Strictly parse and assess raw proof JSON; malformed input returns a fail result."""

    try:
        proof = parse_proof_json(data)
    except ProofDocumentError as exc:
        return _invalid_assessment(str(exc))
    return assess_proof(proof, registry=registry)
