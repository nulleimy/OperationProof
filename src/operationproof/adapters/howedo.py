from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from ..canonical import canonical_json_bytes, sha256_digest, valid_digest
from ..domain import EvidenceEnvelope, Layer, Verdict

_ALLOWED_ACTIONS = {"CONTINUE", "PAUSE", "REVALIDATE", "ABORT", "RECOVER"}
_BINDING_SCHEMA = "operationproof.howedo-binding.v1"


class HowedoWitnessError(ValueError):
    """Raised when HOWEDO witness input or its trusted binding fails validation."""


BindingVerifier = Callable[[Mapping[str, Any]], bool]


def _snapshot_document(document: Mapping[str, Any], code: str) -> dict[str, Any]:
    try:
        snapshot = json.loads(canonical_json_bytes(dict(document)).decode("utf-8"))
    except (TypeError, ValueError, OverflowError, json.JSONDecodeError) as exc:
        raise HowedoWitnessError(code) from exc
    if not isinstance(snapshot, dict):
        raise HowedoWitnessError(code)
    return snapshot


def _parse_timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise HowedoWitnessError(code)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HowedoWitnessError(code) from exc
    if parsed.tzinfo is None:
        raise HowedoWitnessError(code)
    return parsed.astimezone(UTC)


def _binding_payload(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": binding.get("schema"),
        "operation_id": binding.get("operation_id"),
        "snapshot_id": binding.get("snapshot_id"),
        "witness_digest": binding.get("witness_digest"),
        "issued_at": binding.get("issued_at"),
        "expires_at": binding.get("expires_at"),
    }


class HowedoWitnessAdapter:
    """Translate a HOWEDO ContinuityWitness into OperationProof continuity evidence.

    A native HOWEDO witness proves continuity state, but does not itself bind an
    OperationProof operation identifier or freshness window. Therefore a PASS can
    be emitted only when an external trusted verifier attests a binding that covers
    the operation, snapshot, witness digest, issued time, and mandatory expiry.
    """

    layer = Layer.CONTINUITY
    provider_id = "howedo"
    protocol = "howedo.continuity-witness.v1"
    binding_protocol = _BINDING_SCHEMA

    @classmethod
    def adapt(
        cls,
        *,
        operation_id: str,
        witness: Mapping[str, Any],
        binding: Mapping[str, Any],
        binding_verifier: BindingVerifier,
    ) -> EvidenceEnvelope:
        if not isinstance(operation_id, str) or not operation_id:
            raise HowedoWitnessError("INVALID_OPERATION_ID")
        if not isinstance(witness, Mapping):
            raise HowedoWitnessError("INVALID_HOWEDO_WITNESS")
        if not isinstance(binding, Mapping):
            raise HowedoWitnessError("INVALID_HOWEDO_BINDING")
        if not callable(binding_verifier):
            raise HowedoWitnessError("INVALID_BINDING_VERIFIER")

        witness_snapshot = _snapshot_document(witness, "INVALID_HOWEDO_WITNESS")
        binding_snapshot = _snapshot_document(binding, "INVALID_HOWEDO_BINDING")

        snapshot_id = witness_snapshot.get("snapshot_id")
        action = witness_snapshot.get("action")
        reason_codes = witness_snapshot.get("reason_codes")
        witness_digest = witness_snapshot.get("witness_digest")

        if not isinstance(snapshot_id, str) or not valid_digest(snapshot_id):
            raise HowedoWitnessError("INVALID_SNAPSHOT_ID")
        if not isinstance(action, str) or action not in _ALLOWED_ACTIONS:
            raise HowedoWitnessError("INVALID_HOWEDO_ACTION")
        if not isinstance(reason_codes, (list, tuple)) or not all(
            isinstance(reason, str) and reason for reason in reason_codes
        ):
            raise HowedoWitnessError("INVALID_REASON_CODES")
        if not isinstance(witness_digest, str) or not valid_digest(witness_digest):
            raise HowedoWitnessError("INVALID_HOWEDO_WITNESS_DIGEST")

        canonical_reasons = tuple(sorted(reason_codes))
        expected_witness_digest = sha256_digest(
            {
                "action": action,
                "reason_codes": canonical_reasons,
                "snapshot_id": snapshot_id,
            }
        )
        if witness_digest != expected_witness_digest:
            raise HowedoWitnessError("HOWEDO_WITNESS_DIGEST_MISMATCH")

        if binding_snapshot.get("schema") != _BINDING_SCHEMA:
            raise HowedoWitnessError("INVALID_BINDING_SCHEMA")
        if binding_snapshot.get("operation_id") != operation_id:
            raise HowedoWitnessError("BINDING_OPERATION_ID_MISMATCH")
        if binding_snapshot.get("snapshot_id") != snapshot_id:
            raise HowedoWitnessError("BINDING_SNAPSHOT_ID_MISMATCH")
        if binding_snapshot.get("witness_digest") != witness_digest:
            raise HowedoWitnessError("BINDING_WITNESS_DIGEST_MISMATCH")

        issued_at = binding_snapshot.get("issued_at")
        expires_at = binding_snapshot.get("expires_at")
        issued = _parse_timestamp(issued_at, "INVALID_BINDING_ISSUED_AT")
        expires = _parse_timestamp(expires_at, "INVALID_BINDING_EXPIRES_AT")
        if expires <= issued:
            raise HowedoWitnessError("INVALID_BINDING_TIME_WINDOW")

        binding_digest = binding_snapshot.get("binding_digest")
        if not isinstance(binding_digest, str) or not valid_digest(binding_digest):
            raise HowedoWitnessError("INVALID_BINDING_DIGEST")
        expected_binding_digest = sha256_digest(_binding_payload(binding_snapshot))
        if binding_digest != expected_binding_digest:
            raise HowedoWitnessError("BINDING_DIGEST_MISMATCH")

        try:
            verifier_binding = _snapshot_document(binding_snapshot, "INVALID_HOWEDO_BINDING")
            trusted = binding_verifier(verifier_binding)
        except Exception as exc:
            raise HowedoWitnessError("BINDING_VERIFICATION_ERROR") from exc
        if trusted is not True:
            raise HowedoWitnessError("UNTRUSTED_HOWEDO_BINDING")

        verdict = Verdict.PASS if action == "CONTINUE" else Verdict.FAIL
        subject_digest = sha256_digest(
            {
                "operation_id": operation_id,
                "snapshot_id": snapshot_id,
            }
        )
        evidence_digest = sha256_digest(
            {
                "binding_digest": binding_digest,
                "witness_digest": witness_digest,
            }
        )

        return EvidenceEnvelope(
            layer=Layer.CONTINUITY,
            provider=cls.provider_id,
            operation_id=operation_id,
            decision=action,
            verdict=verdict,
            subject_digest=subject_digest,
            evidence_digest=evidence_digest,
            issued_at=str(issued_at),
            expires_at=str(expires_at),
            metadata={
                "adapter": "operationproof.howedo.v1",
                "binding": "externally-verified-operation-binding",
                "binding_digest": binding_digest,
                "binding_protocol": cls.binding_protocol,
                "howedo_protocol": cls.protocol,
                "howedo_snapshot_id": snapshot_id,
                "howedo_witness_digest": witness_digest,
                "howedo_reason_codes": list(canonical_reasons),
            },
        )
