from copy import deepcopy

from operationproof.adapters.execution import (
    SandCloudExecutionReceiptAdapter,
    make_execution_receipt_trust_verifier,
)
from operationproof.canonical import sha256_digest
from operationproof.trust import TrustVerificationContext


def _receipt(pre_digest: str) -> dict[str, str]:
    receipt = {
        "schema": "operationproof.execution-receipt.v1",
        "provider": "sandcloud",
        "receipt_id": "sandcloud-envelope-rebind",
        "operation_id": "op-envelope-rebind",
        "pre_proof_digest": pre_digest,
        "status": "SUCCEEDED",
        "result_digest": sha256_digest({"result": "ok"}),
        "started_at": "2026-08-23T00:00:00+00:00",
        "completed_at": "2026-08-23T00:00:02+00:00",
    }
    receipt["receipt_digest"] = sha256_digest(receipt)
    return receipt


def _fixture() -> tuple[dict[str, object], object, TrustVerificationContext]:
    pre_digest = sha256_digest({"pre": "envelope-rebind"})
    receipt = _receipt(pre_digest)
    evidence = SandCloudExecutionReceiptAdapter.adapt(
        operation_id="op-envelope-rebind",
        pre_proof_digest=pre_digest,
        receipt=receipt,
        receipt_verifier=lambda item: True,
    ).to_dict()
    verifier = make_execution_receipt_trust_verifier(
        provider_id="sandcloud",
        receipt_resolver=lambda digest: receipt if digest == receipt["receipt_digest"] else None,
        receipt_verifier=lambda item: True,
    )
    context = TrustVerificationContext(
        root_phase="FINAL",
        evidence_phase="FINAL",
        operation_id="op-envelope-rebind",
        proof_digest=sha256_digest({"final": "proof"}),
        pre_proof_digest=pre_digest,
        evidence_index=0,
    )
    return evidence, verifier, context


def test_exact_adapter_envelope_is_reproducibly_trusted() -> None:
    evidence, verifier, context = _fixture()
    assert verifier(evidence, context) is True


def test_extra_execution_metadata_is_rejected() -> None:
    evidence, verifier, context = _fixture()
    tampered = deepcopy(evidence)
    tampered["metadata"]["untrusted_note"] = "looks-safe"
    assert verifier(tampered, context) is False


def test_execution_issued_at_must_reproduce_from_receipt() -> None:
    evidence, verifier, context = _fixture()
    tampered = deepcopy(evidence)
    tampered["issued_at"] = "2026-08-23T01:00:00+00:00"
    assert verifier(tampered, context) is False


def test_extra_execution_envelope_field_is_rejected() -> None:
    evidence, verifier, context = _fixture()
    tampered = deepcopy(evidence)
    tampered["trusted"] = True
    assert verifier(tampered, context) is False
