import pytest

from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.subject import OperationSubject, OperationSubjectError
from operationproof.verifier import verify_proof


def subject(operation_id: str = "op-r6") -> OperationSubject:
    return OperationSubject(
        operation_id=operation_id,
        actor_digest=sha256_digest({"actor": "alice"}),
        intent_digest=sha256_digest({"intent": "deploy", "payload": "v1"}),
        target_digest=sha256_digest({"target": "service-a"}),
        state_digest=sha256_digest({"state": "revision-17"}),
    )


def evidence(
    layer: Layer,
    *,
    operation_subject: OperationSubject,
    subject_digest: str | None = None,
) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"test:{layer.value}",
        operation_id=operation_subject.operation_id,
        decision="native-ok",
        verdict=Verdict.PASS,
        subject_digest=subject_digest or operation_subject.digest,
        evidence_digest=sha256_digest({"evidence": layer.value}),
        issued_at="2026-08-23T00:00:00+00:00",
    )


def test_operation_subject_digest_is_deterministic() -> None:
    first = subject()
    second = subject()

    assert first.to_dict() == second.to_dict()
    assert first.digest == second.digest
    assert first.digest == sha256_digest(first.to_dict())


def test_operation_subject_rejects_noncanonical_component_digest() -> None:
    with pytest.raises(
        OperationSubjectError,
        match="INVALID_OPERATION_SUBJECT_ACTOR_DIGEST",
    ):
        OperationSubject(
            operation_id="op-r6",
            actor_digest="alice",
            intent_digest=sha256_digest({"intent": "deploy"}),
            target_digest=sha256_digest({"target": "service-a"}),
            state_digest=sha256_digest({"state": "revision-17"}),
        )


def test_subject_bound_pre_requires_same_subject_across_all_layers() -> None:
    operation_subject = subject()
    proof = build_pre_proof(
        operation_subject.operation_id,
        [
            evidence(layer, operation_subject=operation_subject)
            for layer in PRE_LAYERS
        ],
        subject=operation_subject,
    )

    assert proof["schema"] == "operationproof.operation-proof.v2"
    assert proof["subject"] == operation_subject.to_dict()
    assert proof["subject_digest"] == operation_subject.digest
    assert proof["decision"] == "VERIFIED"
    assert verify_proof(proof).valid is True


def test_one_pre_layer_for_another_subject_is_rejected_but_integrity_valid() -> None:
    operation_subject = subject()
    other_subject = subject("op-other")
    items = [
        evidence(layer, operation_subject=operation_subject)
        for layer in PRE_LAYERS
    ]
    items[2] = evidence(
        Layer.INTENT,
        operation_subject=operation_subject,
        subject_digest=other_subject.digest,
    )

    proof = build_pre_proof(
        operation_subject.operation_id,
        items,
        subject=operation_subject,
    )

    assert proof["decision"] == "REJECTED"
    assert "SUBJECT_DIGEST_MISMATCH:intent" in proof["reason_codes"]
    assert verify_proof(proof).valid is True


def test_subject_bound_final_requires_execution_for_exact_same_subject() -> None:
    operation_subject = subject()
    pre = build_pre_proof(
        operation_subject.operation_id,
        [
            evidence(layer, operation_subject=operation_subject)
            for layer in PRE_LAYERS
        ],
        subject=operation_subject,
    )
    execution = evidence(Layer.EXECUTION, operation_subject=operation_subject)

    final = build_final_proof(pre, execution)

    assert final["schema"] == "operationproof.operation-proof.v2"
    assert final["subject"] == pre["subject"]
    assert final["subject_digest"] == pre["subject_digest"]
    assert final["decision"] == "VERIFIED"
    assert verify_proof(final).valid is True


def test_execution_for_different_subject_cannot_complete_final() -> None:
    operation_subject = subject()
    pre = build_pre_proof(
        operation_subject.operation_id,
        [
            evidence(layer, operation_subject=operation_subject)
            for layer in PRE_LAYERS
        ],
        subject=operation_subject,
    )
    execution = evidence(
        Layer.EXECUTION,
        operation_subject=operation_subject,
        subject_digest=subject("other-operation").digest,
    )

    final = build_final_proof(pre, execution)

    assert final["decision"] == "REJECTED"
    assert "SUBJECT_DIGEST_MISMATCH:execution" in final["reason_codes"]
    assert verify_proof(final).valid is True


def test_v1_final_cannot_wrap_v2_pre_to_drop_subject_binding() -> None:
    operation_subject = subject()
    pre = build_pre_proof(
        operation_subject.operation_id,
        [
            evidence(layer, operation_subject=operation_subject)
            for layer in PRE_LAYERS
        ],
        subject=operation_subject,
    )
    execution = evidence(
        Layer.EXECUTION,
        operation_subject=operation_subject,
        subject_digest=subject("different-subject").digest,
    )
    final = {
        "schema": "operationproof.operation-proof.v1",
        "phase": "FINAL",
        "operation_id": operation_subject.operation_id,
        "decision": "VERIFIED",
        "reason_codes": [],
        "pre_proof_digest": pre["proof_digest"],
        "pre_proof": pre,
        "evidence": [execution.to_dict()],
    }
    final["proof_digest"] = sha256_digest(final)

    result = verify_proof(final)

    assert result.valid is False
    assert "PRE_PROOF_SCHEMA_MISMATCH" in result.reason_codes
    assert "DECISION_MISMATCH" not in result.reason_codes


def test_tampered_subject_payload_is_integrity_failure() -> None:
    operation_subject = subject()
    proof = build_pre_proof(
        operation_subject.operation_id,
        [
            evidence(layer, operation_subject=operation_subject)
            for layer in PRE_LAYERS
        ],
        subject=operation_subject,
    )
    proof["subject"]["target_digest"] = sha256_digest({"target": "tampered"})
    proof["proof_digest"] = sha256_digest(
        {key: value for key, value in proof.items() if key != "proof_digest"}
    )

    result = verify_proof(proof)

    assert result.valid is False
    assert "OPERATION_SUBJECT_DIGEST_MISMATCH" in result.reason_codes


def test_v1_proof_remains_read_compatible() -> None:
    items = [
        EvidenceEnvelope(
            layer=layer,
            provider=f"legacy:{layer.value}",
            operation_id="legacy-op",
            decision="legacy-ok",
            verdict=Verdict.PASS,
            subject_digest=sha256_digest({"legacy-subject": layer.value}),
            evidence_digest=sha256_digest({"legacy-evidence": layer.value}),
            issued_at="2026-08-23T00:00:00+00:00",
        )
        for layer in PRE_LAYERS
    ]

    proof = build_pre_proof("legacy-op", items)

    assert proof["schema"] == "operationproof.operation-proof.v1"
    assert "subject" not in proof
    assert "subject_digest" not in proof
    assert proof["decision"] == "VERIFIED"
    assert verify_proof(proof).valid is True
