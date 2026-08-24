from __future__ import annotations

from datetime import UTC, datetime

import pytest

import operationproof
from operationproof.attestation import AttestationSigner
from operationproof.attestation_store import (
    AttestationStore,
    AttestationStoreHead,
    AttestationStoreError,
)
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS
from operationproof.provenance import ProvenanceRecorderError

NOW = datetime(2026, 8, 24, 4, 0, tzinfo=UTC)
ISSUED = "2026-08-24T03:00:00+00:00"
SECRET = b"r11-reference-secret-material-32bytes!!"


def _signer() -> operationproof.HMACSHA256Signer:
    return operationproof.HMACSHA256Signer(
        issuer_id="issuer:test",
        key_id="key:test",
        secret=SECRET,
    )


def _verifier(
    *,
    issuer_id: str = "issuer:test",
    key_id: str = "key:test",
    secret: bytes = SECRET,
) -> operationproof.HMACSHA256Verifier:
    return operationproof.HMACSHA256Verifier(
        issuer_id=issuer_id,
        key_id=key_id,
        secret=secret,
    )


def _attestation(
    *,
    sequence: int = 0,
    previous: str = operationproof.ATTESTATION_GENESIS,
    operation_id: str = "op-r11",
    subject_digest: str | None = None,
    proof_digest: str | None = None,
    issued_at: str = ISSUED,
) -> dict[str, object]:
    return operationproof.build_attestation(
        attestation_id=f"att-{sequence}",
        operation_id=operation_id,
        subject_digest=subject_digest or sha256_digest({"subject": "r11"}),
        proof_digest=proof_digest or sha256_digest({"proof": "pre"}),
        artifact_type="proof_assessed",
        artifact_digest=sha256_digest({"artifact": sequence}),
        issuer_id="issuer:test",
        issued_at=issued_at,
        sequence=sequence,
        previous_attestation_digest=previous,
        payload_digest=sha256_digest({"event": sequence}),
    )


def _signed(attestation: dict[str, object] | None = None) -> dict[str, object]:
    return operationproof.sign_attestation(attestation or _attestation(), _signer())


def _registry(
    verifier: operationproof.HMACSHA256Verifier | None = None,
) -> dict[tuple[str, str, str], operationproof.HMACSHA256Verifier]:
    verifier = verifier or _verifier()
    return {(verifier.issuer_id, verifier.algorithm, verifier.key_id): verifier}


def test_valid_signed_attestation_and_deterministic_canonical_json() -> None:
    attestation = _attestation()
    assert operationproof.canonical_attestation_json(attestation) == (
        operationproof.canonical_attestation_json(dict(reversed(list(attestation.items()))))
    )
    result = operationproof.verify_attestation_signature(
        _signed(attestation),
        _verifier(),
        now=NOW,
    )
    assert result.valid is True
    assert result.integrity_valid is True
    assert result.signature_valid is True


def test_tampered_payload_rejected() -> None:
    signed = _signed()
    signed["attestation"]["artifact_digest"] = sha256_digest({"tampered": True})
    result = operationproof.verify_attestation_signature(signed, _verifier(), now=NOW)
    assert result.valid is False
    assert "ATTESTATION_DIGEST_MISMATCH" in result.reason_codes


def test_tampered_signature_rejected() -> None:
    signed = _signed()
    signature = signed["signature"]["signature"]
    signed["signature"]["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    result = operationproof.verify_attestation_signature(signed, _verifier(), now=NOW)
    assert result.valid is False
    assert "ATTESTATION_SIGNATURE_INVALID" in result.reason_codes


def test_wrong_issuer_rejected() -> None:
    result = operationproof.verify_attestation_signature(
        _signed(),
        _verifier(issuer_id="issuer:wrong"),
        now=NOW,
    )
    assert result.valid is False
    assert "SIGNATURE_ISSUER_TRUST_MISMATCH" in result.reason_codes


@pytest.mark.parametrize(
    ("field", "expected_key", "reason"),
    [
        ("operation_id", "other-op", "EXPECTED_OPERATION_ID_MISMATCH"),
        ("subject_digest", sha256_digest({"other": "subject"}), "EXPECTED_SUBJECT_DIGEST_MISMATCH"),
        ("proof_digest", sha256_digest({"other": "proof"}), "EXPECTED_PROOF_DIGEST_MISMATCH"),
    ],
)
def test_chain_expected_binding_mismatch_rejected(
    field: str,
    expected_key: str,
    reason: str,
) -> None:
    kwargs = {
        "expected_operation_id": "op-r11",
        "expected_subject_digest": sha256_digest({"subject": "r11"}),
        "expected_proof_digest": sha256_digest({"proof": "pre"}),
    }
    kwargs[f"expected_{field}"] = expected_key
    result = operationproof.verify_provenance_chain(
        [_signed()],
        verifiers=_registry(),
        now=NOW,
        **kwargs,
    )
    assert result.valid is False
    assert reason in result.reason_codes


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("operation_id", "op-transplanted", "CROSS_OPERATION_TRANSPLANT"),
        (
            "subject_digest",
            sha256_digest({"subject": "transplanted"}),
            "SUBJECT_TRANSPLANT",
        ),
        (
            "proof_digest",
            sha256_digest({"proof": "transplanted"}),
            "PROOF_TRANSPLANT",
        ),
    ],
)
def test_chain_transplant_rejected(field: str, value: str, reason: str) -> None:
    first = _attestation(sequence=0)
    first_signed = _signed(first)
    kwargs = {
        "operation_id": "op-r11",
        "subject_digest": sha256_digest({"subject": "r11"}),
        "proof_digest": sha256_digest({"proof": "pre"}),
    }
    kwargs[field] = value
    second = _attestation(
        sequence=1,
        previous=first["attestation_digest"],
        operation_id=kwargs["operation_id"],
        subject_digest=kwargs["subject_digest"],
        proof_digest=kwargs["proof_digest"],
    )
    second["attestation_id"] = f"att-transplant-{field}"
    second["attestation_digest"] = sha256_digest(operationproof.attestation_payload(second))
    result = operationproof.verify_provenance_chain(
        [first_signed, _signed(second)],
        verifiers=_registry(),
        now=NOW,
    )
    assert result.valid is False
    assert reason in result.reason_codes


def test_broken_previous_link_and_duplicate_sequence_rejected() -> None:
    first = _attestation(sequence=0)
    first_signed = _signed(first)
    second = _attestation(
        sequence=0,
        previous=operationproof.ATTESTATION_GENESIS,
    )
    second["attestation_id"] = "att-second"
    second["attestation_digest"] = sha256_digest(
        operationproof.attestation_payload(second)
    )
    result = operationproof.verify_provenance_chain(
        [first_signed, _signed(second)],
        verifiers=_registry(),
        now=NOW,
    )
    assert result.valid is False
    assert "PROVENANCE_SEQUENCE_MISMATCH" in result.reason_codes
    assert "BROKEN_PREDECESSOR_LINK" in result.reason_codes


def test_reordered_chain_rejected() -> None:
    first = _attestation(sequence=0)
    first_signed = _signed(first)
    second = _attestation(
        sequence=1,
        previous=first["attestation_digest"],
    )
    second_signed = _signed(second)
    result = operationproof.verify_provenance_chain(
        [second_signed, first_signed],
        verifiers=_registry(),
        now=NOW,
    )
    assert result.valid is False
    assert "PROVENANCE_SEQUENCE_MISMATCH" in result.reason_codes


def test_replayed_attestation_rejected() -> None:
    signed = _signed()
    result = operationproof.verify_provenance_chain(
        [signed, signed],
        verifiers=_registry(),
        now=NOW,
    )
    assert result.valid is False
    assert "REPLAYED_ATTESTATION_ID" in result.reason_codes
    assert "REPLAYED_ATTESTATION_DIGEST" in result.reason_codes


def test_future_issued_at_rejected() -> None:
    future = _attestation(issued_at="2026-08-25T03:00:00+00:00")
    result = operationproof.verify_attestation_signature(
        _signed(future),
        _verifier(),
        now=NOW,
    )
    assert result.valid is False
    assert "ATTESTATION_ISSUED_IN_FUTURE" in result.reason_codes


class _MalformedVerifier(operationproof.AttestationVerifier):
    algorithm = operationproof.HMAC_SHA256_V1
    issuer_id = "issuer:test"
    key_id = "key:test"

    def verify(self, payload: bytes, signature: str):
        del payload, signature
        return "not-a-bool"


def test_malformed_signature_verifier_output_rejected() -> None:
    result = operationproof.verify_attestation_signature(
        _signed(),
        _MalformedVerifier(),
        now=NOW,
    )
    assert result.valid is False
    assert "MALFORMED_SIGNATURE_VERIFIER_OUTPUT" in result.reason_codes


def test_attestation_unknown_field_rejected() -> None:
    attestation = _attestation()
    attestation["authority"] = "VERIFIED"
    attestation["attestation_digest"] = sha256_digest(
        operationproof.attestation_payload(attestation)
    )
    result = operationproof.verify_attestation_integrity(attestation, now=NOW)
    assert result.valid is False
    assert "ATTESTATION_FIELD_SET_MISMATCH" in result.reason_codes


class _MalformedSigner(AttestationSigner):
    algorithm = "test.invalid.v1"
    issuer_id = "issuer:test"
    key_id = "key:test"

    def sign(self, payload: bytes) -> str:
        del payload
        return "!"


def test_malformed_signature_adapter_output_rejected() -> None:
    with pytest.raises(ValueError, match="MALFORMED_SIGNATURE_ADAPTER_OUTPUT"):
        operationproof.sign_attestation(_attestation(), _MalformedSigner())


class _MutatingSigner(operationproof.HMACSHA256Signer):
    def __init__(self, source: dict[str, object]) -> None:
        super().__init__(issuer_id="issuer:test", key_id="key:test", secret=SECRET)
        self.source = source

    def sign(self, payload: bytes) -> str:
        self.source["operation_id"] = "attacker-mutated"
        return super().sign(payload)


def test_signer_mutation_cannot_change_signed_snapshot() -> None:
    source = _attestation()
    signed = operationproof.sign_attestation(source, _MutatingSigner(source))
    assert source["operation_id"] == "attacker-mutated"
    assert signed["attestation"]["operation_id"] == "op-r11"
    assert operationproof.verify_attestation_signature(
        signed,
        _verifier(),
        now=NOW,
    ).valid


class _MutatingOutputStore(AttestationStore):
    def head(self, operation_id: str) -> AttestationStoreHead | None:
        del operation_id
        return None

    def append(
        self,
        signed_attestation: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_attestation_digest: str,
    ) -> AttestationStoreHead:
        del expected_previous_attestation_digest
        attestation = signed_attestation["attestation"]
        return AttestationStoreHead(
            operation_id=attestation["operation_id"],
            subject_digest=attestation["subject_digest"],
            proof_digest=attestation["proof_digest"],
            sequence=expected_sequence,
            attestation_id=attestation["attestation_id"],
            attestation_digest=sha256_digest({"mutated": True}),
        )

    def read(self, operation_id: str, sequence: int):
        del operation_id, sequence
        return None


class _MutatingReadbackStore(AttestationStore):
    def __init__(self) -> None:
        self.inner = operationproof.MemoryAttestationStore()

    def head(self, operation_id: str) -> AttestationStoreHead | None:
        return self.inner.head(operation_id)

    def append(
        self,
        signed_attestation: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_attestation_digest: str,
    ) -> AttestationStoreHead:
        return self.inner.append(
            signed_attestation,
            expected_sequence=expected_sequence,
            expected_previous_attestation_digest=expected_previous_attestation_digest,
        )

    def read(self, operation_id: str, sequence: int):
        value = self.inner.read(operation_id, sequence)
        assert isinstance(value, dict)
        value["attestation"]["artifact_digest"] = sha256_digest({"tampered": True})
        return value


class _FailingTelemetry(operationproof.TelemetrySink):
    def emit(self, event: dict[str, object]) -> None:
        del event
        raise RuntimeError("telemetry unavailable")


class _FailingAppendStore(AttestationStore):
    def head(self, operation_id: str) -> AttestationStoreHead | None:
        del operation_id
        return None

    def append(
        self,
        signed_attestation: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_attestation_digest: str,
    ) -> AttestationStoreHead:
        del signed_attestation, expected_sequence, expected_previous_attestation_digest
        raise AttestationStoreError("backend unavailable")

    def read(self, operation_id: str, sequence: int):
        del operation_id, sequence
        return None


def _recorder(
    store: AttestationStore,
    telemetry: operationproof.TelemetrySink | None = None,
) -> operationproof.ProvenanceRecorder:
    return operationproof.ProvenanceRecorder(
        signer=_signer(),
        verifier=_verifier(),
        store=store,
        telemetry_sink=telemetry,
        clock=lambda: NOW,
    )


def _record(recorder: operationproof.ProvenanceRecorder):
    return recorder.record_event(
        event_type="proof_assessed",
        operation_id="op-r11",
        subject_digest=sha256_digest({"subject": "r11"}),
        proof_digest=sha256_digest({"proof": "pre"}),
        artifact_digest=sha256_digest({"artifact": "proof"}),
    )


def test_external_store_output_mutation_rejected_fail_closed() -> None:
    with pytest.raises(ProvenanceRecorderError, match="ATTESTATION_STORE_APPEND_FAILED"):
        _record(_recorder(_MutatingOutputStore()))


def test_external_store_readback_mutation_rejected_fail_closed() -> None:
    with pytest.raises(ProvenanceRecorderError, match="ATTESTATION_STORE_APPEND_FAILED"):
        _record(_recorder(_MutatingReadbackStore()))


def test_required_provenance_persistence_failure_is_fail_closed() -> None:
    with pytest.raises(ProvenanceRecorderError, match="ATTESTATION_STORE_APPEND_FAILED"):
        _record(_recorder(_FailingAppendStore()))


def test_best_effort_telemetry_failure_does_not_change_provenance_result() -> None:
    store = operationproof.MemoryAttestationStore()
    result = _record(_recorder(store, _FailingTelemetry()))
    assert result.persisted is True
    assert result.telemetry_exported is False
    assert len(store.records("op-r11")) == 1


def test_execution_receipt_attestation_does_not_promote_execution_semantics() -> None:
    store = operationproof.MemoryAttestationStore()
    recorder = _recorder(store)
    pre_digest = sha256_digest({"proof": "pre"})
    subject_digest = sha256_digest({"subject": "r11"})
    receipt = operationproof.build_execution_receipt(
        provider="caser",
        operation_id="op-r11",
        pre_proof_digest=pre_digest,
        execution_instance_id="exec-r11",
        effect_class=operationproof.ExecutionEffect.MUTATING,
        outcome=operationproof.ExecutionOutcome.SUCCEEDED,
        native_receipt_digest=sha256_digest({"native": "receipt"}),
        native_verification_digest=sha256_digest({"native": "verification"}),
        receipt_integrity_verified=True,
        execution_outcome_verified=True,
        provider_post_state_verified=True,
        issued_at="2026-08-24T03:00:00+00:00",
        expires_at="2030-01-01T00:00:00+00:00",
    )
    result = operationproof.attest_execution_receipt(
        recorder,
        receipt,
        subject_digest=subject_digest,
        pre_proof_digest=pre_digest,
    )
    assert result.persisted is True
    signed = store.records("op-r11")[0]
    assert signed["attestation"]["artifact_type"] == "execution_receipt_verified"
    assert receipt["outcome"] == "SUCCEEDED"
    assert "decision" not in signed["attestation"]


def test_final_proof_attestation_preserves_rejected_semantic_decision() -> None:
    operation_id = "op-r11-final"
    subject = operationproof.OperationSubject(
        operation_id=operation_id,
        actor_digest=sha256_digest({"actor": "r11-final"}),
        intent_digest=sha256_digest({"intent": "r11-final"}),
        target_digest=sha256_digest({"target": "r11-final"}),
        state_digest=sha256_digest({"state": "r11-final"}),
    )
    pre_evidence = [
        operationproof.EvidenceEnvelope(
            layer=layer,
            provider=f"r11:{layer.value}",
            operation_id=operation_id,
            decision="ok",
            verdict=operationproof.Verdict.PASS,
            subject_digest=subject.digest,
            evidence_digest=sha256_digest({"layer": layer.value}),
            issued_at="2026-08-24T03:00:00+00:00",
            expires_at="2030-01-01T00:00:00+00:00",
        )
        for layer in PRE_LAYERS
    ]
    pre = operationproof.build_pre_proof(operation_id, pre_evidence, subject=subject)
    execution = operationproof.EvidenceEnvelope(
        layer=operationproof.Layer.EXECUTION,
        provider="r11:execution",
        operation_id=operation_id,
        decision="native-failed",
        verdict=operationproof.Verdict.FAIL,
        subject_digest=subject.digest,
        evidence_digest=sha256_digest({"execution": "failed"}),
        issued_at="2026-08-24T03:30:00+00:00",
        expires_at="2030-01-01T00:00:00+00:00",
    )
    final = operationproof.build_final_proof(pre, execution)
    assert final["decision"] == operationproof.ProofDecision.REJECTED.value

    store = operationproof.MemoryAttestationStore()
    recorder = _recorder(store)
    result = operationproof.attest_final_proof(
        recorder,
        final,
        subject_digest=subject.digest,
        pre_proof_digest=pre["proof_digest"],
    )
    assert result.persisted is True
    signed = store.records(operation_id)[0]
    assert signed["attestation"]["artifact_type"] == "final_proof_composed"
    assert final["decision"] == operationproof.ProofDecision.REJECTED.value
