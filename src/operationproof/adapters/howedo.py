from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..canonical import sha256_digest, valid_digest
from ..domain import EvidenceEnvelope, Layer, Verdict

_ALLOWED_ACTIONS = {"CONTINUE", "PAUSE", "REVALIDATE", "ABORT", "RECOVER"}


class HowedoWitnessError(ValueError):
    """Raised when HOWEDO witness input is malformed or fails integrity checks."""


class HowedoWitnessAdapter:
    """Translate a HOWEDO ContinuityWitness into OperationProof continuity evidence.

    The adapter is intentionally dependency-free. It validates HOWEDO's canonical
    witness shape and independently recomputes the witness digest before producing
    an EvidenceEnvelope.
    """

    layer = Layer.CONTINUITY
    provider_id = "howedo"
    protocol = "howedo.continuity-witness.v1"

    @classmethod
    def adapt(
        cls,
        *,
        operation_id: str,
        witness: Mapping[str, Any],
        issued_at: str,
        expires_at: str | None = None,
    ) -> EvidenceEnvelope:
        if not isinstance(operation_id, str) or not operation_id:
            raise HowedoWitnessError("INVALID_OPERATION_ID")
        if not isinstance(witness, Mapping):
            raise HowedoWitnessError("INVALID_HOWEDO_WITNESS")
        if not isinstance(issued_at, str) or not issued_at:
            raise HowedoWitnessError("INVALID_ISSUED_AT")
        if expires_at is not None and (not isinstance(expires_at, str) or not expires_at):
            raise HowedoWitnessError("INVALID_EXPIRES_AT")

        snapshot_id = witness.get("snapshot_id")
        action = witness.get("action")
        reason_codes = witness.get("reason_codes")
        witness_digest = witness.get("witness_digest")

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
        expected_digest = sha256_digest(
            {
                "action": action,
                "reason_codes": canonical_reasons,
                "snapshot_id": snapshot_id,
            }
        )
        if witness_digest != expected_digest:
            raise HowedoWitnessError("HOWEDO_WITNESS_DIGEST_MISMATCH")

        # Only CONTINUE authorizes the original operation to proceed now. PAUSE,
        # REVALIDATE, ABORT, and RECOVER all require another control-flow step first.
        verdict = Verdict.PASS if action == "CONTINUE" else Verdict.FAIL
        subject_digest = sha256_digest(
            {
                "operation_id": operation_id,
                "snapshot_id": snapshot_id,
            }
        )

        return EvidenceEnvelope(
            layer=Layer.CONTINUITY,
            provider=cls.provider_id,
            operation_id=operation_id,
            decision=action,
            verdict=verdict,
            subject_digest=subject_digest,
            evidence_digest=witness_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            metadata={
                "adapter": "operationproof.howedo.v1",
                "binding": "adapter-attached-operation-id",
                "howedo_protocol": cls.protocol,
                "howedo_snapshot_id": snapshot_id,
                "howedo_reason_codes": list(canonical_reasons),
            },
        )
