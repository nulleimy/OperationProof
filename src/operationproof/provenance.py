from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .attestation import (
    AttestationSigner,
    AttestationVerifier,
    GENESIS,
    build_attestation,
    sign_attestation,
    verify_attestation_signature,
)
from .attestation_store import (
    AttestationStore,
    AttestationStoreError,
    validate_attestation_store_head,
)
from .canonical import canonical_json_bytes, valid_digest
from .execution import verify_execution_receipt
from .observability import (
    TelemetrySink,
    build_observability_event,
    emit_telemetry_best_effort,
)
from .verifier import verify_proof


class ProvenanceRecorderError(RuntimeError):
    """Security-critical provenance could not be established or persisted."""


@dataclass(frozen=True, slots=True)
class ProvenanceRecordResult:
    persisted: bool
    telemetry_exported: bool
    event_digest: str
    attestation_digest: str
    sequence: int


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ProvenanceRecorderError("INVALID_PROVENANCE_CLOCK")
    return value.astimezone(UTC)


class ProvenanceRecorder:
    """Signs and atomically appends provenance without changing proof authority semantics."""

    def __init__(
        self,
        *,
        signer: AttestationSigner,
        verifier: AttestationVerifier,
        store: AttestationStore,
        telemetry_sink: TelemetrySink | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(signer, AttestationSigner):
            raise ProvenanceRecorderError("ATTESTATION_SIGNER_REQUIRED")
        if not isinstance(verifier, AttestationVerifier):
            raise ProvenanceRecorderError("ATTESTATION_VERIFIER_REQUIRED")
        if not isinstance(store, AttestationStore):
            raise ProvenanceRecorderError("ATTESTATION_STORE_REQUIRED")
        self._signer = signer
        self._verifier = verifier
        self._store = store
        self._telemetry_sink = telemetry_sink
        self._clock = clock or (lambda: datetime.now(UTC))

    def record_event(
        self,
        *,
        event_type: str,
        operation_id: str,
        subject_digest: str,
        proof_digest: str,
        artifact_digest: str,
        state_from: str | None = None,
        state_to: str | None = None,
        reason_codes: tuple[str, ...] = (),
    ) -> ProvenanceRecordResult:
        now = _clock_value(self._clock)
        issued_at = now.isoformat(timespec="milliseconds")
        try:
            current = self._store.head(operation_id)
        except Exception as exc:
            raise ProvenanceRecorderError("ATTESTATION_STORE_HEAD_FAILED") from exc

        if current is None:
            sequence = 0
            previous = GENESIS
        else:
            try:
                current = validate_attestation_store_head(
                    current,
                    expected_operation_id=operation_id,
                    expected_subject_digest=subject_digest,
                    expected_proof_digest=proof_digest,
                    expected_sequence=current.sequence,
                )
            except (AttributeError, AttestationStoreError) as exc:
                raise ProvenanceRecorderError("INVALID_ATTESTATION_STORE_HEAD") from exc
            sequence = current.sequence + 1
            previous = current.attestation_digest

        event = build_observability_event(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            operation_id=operation_id,
            subject_digest=subject_digest,
            proof_digest=proof_digest,
            artifact_digest=artifact_digest,
            occurred_at=issued_at,
            state_from=state_from,
            state_to=state_to,
            reason_codes=reason_codes,
        )
        attestation = build_attestation(
            attestation_id=str(uuid.uuid4()),
            operation_id=operation_id,
            subject_digest=subject_digest,
            proof_digest=proof_digest,
            artifact_type=event_type,
            artifact_digest=artifact_digest,
            issuer_id=self._signer.issuer_id,
            issued_at=issued_at,
            sequence=sequence,
            previous_attestation_digest=previous,
            payload_digest=event["event_digest"],
        )
        try:
            signed = sign_attestation(attestation, self._signer)
        except ValueError as exc:
            raise ProvenanceRecorderError(str(exc)) from exc

        signature = verify_attestation_signature(signed, self._verifier, now=now)
        if not signature.valid:
            raise ProvenanceRecorderError(
                "ATTESTATION_SIGNATURE_REJECTED:" + ",".join(signature.reason_codes)
            )

        try:
            output = self._store.append(
                signed,
                expected_sequence=sequence,
                expected_previous_attestation_digest=previous,
            )
            validate_attestation_store_head(
                output,
                expected_operation_id=operation_id,
                expected_subject_digest=subject_digest,
                expected_proof_digest=proof_digest,
                expected_sequence=sequence,
                expected_attestation_id=attestation["attestation_id"],
                expected_attestation_digest=attestation["attestation_digest"],
            )
            stored = self._store.read(operation_id, sequence)
            if not isinstance(stored, Mapping):
                raise AttestationStoreError("ATTESTATION_STORE_READBACK_MISSING")
            stored_signature = verify_attestation_signature(stored, self._verifier, now=now)
            if not stored_signature.valid:
                raise AttestationStoreError("ATTESTATION_STORE_READBACK_INVALID")
            if canonical_json_bytes(dict(stored)) != canonical_json_bytes(signed):
                raise AttestationStoreError("ATTESTATION_STORE_READBACK_MISMATCH")
        except Exception as exc:
            raise ProvenanceRecorderError("ATTESTATION_STORE_APPEND_FAILED") from exc

        telemetry_exported = emit_telemetry_best_effort(self._telemetry_sink, event)
        return ProvenanceRecordResult(
            persisted=True,
            telemetry_exported=telemetry_exported,
            event_digest=event["event_digest"],
            attestation_digest=attestation["attestation_digest"],
            sequence=sequence,
        )


def attest_execution_receipt(
    recorder: ProvenanceRecorder,
    receipt: Mapping[str, Any],
    *,
    subject_digest: str,
    pre_proof_digest: str,
) -> ProvenanceRecordResult:
    verification = verify_execution_receipt(receipt)
    if not verification.valid:
        raise ProvenanceRecorderError(
            "EXECUTION_RECEIPT_NOT_VERIFIED:" + ",".join(verification.reason_codes)
        )
    operation_id = receipt.get("operation_id")
    receipt_pre = receipt.get("pre_proof_digest")
    receipt_digest = receipt.get("receipt_digest")
    if not isinstance(operation_id, str) or not operation_id:
        raise ProvenanceRecorderError("INVALID_EXECUTION_RECEIPT_OPERATION_ID")
    if receipt_pre != pre_proof_digest:
        raise ProvenanceRecorderError("EXECUTION_RECEIPT_PRE_PROOF_MISMATCH")
    if not isinstance(subject_digest, str) or not valid_digest(subject_digest):
        raise ProvenanceRecorderError("INVALID_EXECUTION_RECEIPT_SUBJECT_DIGEST")
    if not isinstance(receipt_digest, str) or not valid_digest(receipt_digest):
        raise ProvenanceRecorderError("INVALID_EXECUTION_RECEIPT_DIGEST")
    return recorder.record_event(
        event_type="execution_receipt_verified",
        operation_id=operation_id,
        subject_digest=subject_digest,
        proof_digest=pre_proof_digest,
        artifact_digest=receipt_digest,
        state_from="EXECUTION_OBSERVED",
        state_to="EXECUTION_RECEIPT_INTEGRITY_VERIFIED",
        reason_codes=verification.reason_codes,
    )


def attest_final_proof(
    recorder: ProvenanceRecorder,
    final_proof: Mapping[str, Any],
    *,
    subject_digest: str,
    pre_proof_digest: str,
) -> ProvenanceRecordResult:
    verification = verify_proof(dict(final_proof))
    if not verification.valid:
        raise ProvenanceRecorderError(
            "FINAL_PROOF_INTEGRITY_INVALID:" + ",".join(verification.reason_codes)
        )
    if final_proof.get("phase") != "FINAL":
        raise ProvenanceRecorderError("FINAL_PROOF_REQUIRED")
    if final_proof.get("subject_digest") != subject_digest:
        raise ProvenanceRecorderError("FINAL_PROOF_SUBJECT_MISMATCH")
    if final_proof.get("pre_proof_digest") != pre_proof_digest:
        raise ProvenanceRecorderError("FINAL_PROOF_PRE_PROOF_MISMATCH")
    operation_id = final_proof.get("operation_id")
    final_digest = final_proof.get("proof_digest")
    if not isinstance(operation_id, str) or not operation_id:
        raise ProvenanceRecorderError("INVALID_FINAL_PROOF_OPERATION_ID")
    if not isinstance(final_digest, str) or not valid_digest(final_digest):
        raise ProvenanceRecorderError("INVALID_FINAL_PROOF_DIGEST")
    decision = final_proof.get("decision")
    decision_code = decision if isinstance(decision, str) else "UNKNOWN"
    return recorder.record_event(
        event_type="final_proof_composed",
        operation_id=operation_id,
        subject_digest=subject_digest,
        proof_digest=pre_proof_digest,
        artifact_digest=final_digest,
        state_from="EXECUTION_RECEIPT_INTEGRITY_VERIFIED",
        state_to="FINAL_PROOF_COMPOSED",
        reason_codes=(f"SEMANTIC_DECISION:{decision_code}",),
    )
