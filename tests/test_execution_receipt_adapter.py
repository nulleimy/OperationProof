from __future__ import annotations

from typing import Any

import pytest

from operationproof.adapters.execution import (
    CaserExecutionReceiptAdapter,
    ExecutionReceiptError,
    SandCloudExecutionReceiptAdapter,
    make_execution_receipt_trust_verifier,
)
from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.trust import ProviderTrustRegistry, verify_proof_trust


def _pre_evidence(layer: Layer) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"test:{layer.value}",
        operation_id="op-r4",
        decision="native-ok",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": layer.value}),
        evidence_digest=sha256_digest({"evidence": layer.value}),
        issued_at="2026-08-23T00:00:00+00:00",
    )


def _receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": receipt["schema"],
        "provider": receipt["provider"],
        "receipt_id": receipt["receipt_id"],
        "operation_id": receipt["operation_id"],
        "pre_proof_digest": receipt["pre_proof_digest"],
        "status": receipt["status"],
        "result_digest": receipt["result_digest"],
        "started_at": receipt["started_at"],
        "completed_at": receipt["completed_at"],
    }


def _receipt(
    *,
    provider: str,
    pre_proof_digest: str,
    status: str = "SUCCEEDED",
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema": "operationproof.execution-receipt.v1",
        "provider": provider,
        "receipt_id": f"{provider}-receipt-1",
        "operation_id": "op-r4",
        "pre_proof_digest": pre_proof_digest,
        "status": status,
        "result_digest": sha256_digest({"result": provider, "status": status}),
        "started_at": "2026-08-23T00:00:00+00:00",
        "completed_at": "2026-08-23T00:00:05+00:00",
    }
    receipt["receipt_digest"] = sha256_digest(_receipt_payload(receipt))
    return receipt


def _pre() -> tuple[list[EvidenceEnvelope], dict[str, Any]]:
    items = [_pre_evidence(layer) for layer in PRE_LAYERS]
    return items, build_pre_proof("op-r4", items)


def test_sandcloud_success_receipt_adapts_to_execution_pass() -> None:
    _, pre = _pre()
    receipt = _receipt(provider="sandcloud", pre_proof_digest=pre["proof_digest"])

    evidence = SandCloudExecutionReceiptAdapter.adapt(
        operation_id="op-r4",
        pre_proof_digest=pre["proof_digest"],
        receipt=receipt,
        receipt_verifier=lambda item: True,
    )

    assert evidence.layer is Layer.EXECUTION
    assert evidence.provider == "sandcloud"
    assert evidence.verdict is Verdict.PASS
    assert evidence.decision == "SUCCEEDED"
    assert evidence.metadata["receipt_digest"] == receipt["receipt_digest"]
    assert evidence.metadata["pre_proof_digest"] == pre["proof_digest"]


def test_caser_failed_receipt_maps_to_execution_fail() -> None:
    _, pre = _pre()
    receipt = _receipt(
        provider="caser",
        pre_proof_digest=pre["proof_digest"],
        status="FAILED",
    )

    evidence = CaserExecutionReceiptAdapter.adapt(
        operation_id="op-r4",
        pre_proof_digest=pre["proof_digest"],
        receipt=receipt,
        receipt_verifier=lambda item: True,
    )

    assert evidence.provider == "caser"
    assert evidence.verdict is Verdict.FAIL
    assert evidence.decision == "FAILED"


def test_receipt_operation_transplant_fails_closed() -> None:
    _, pre = _pre()
    receipt = _receipt(provider="sandcloud", pre_proof_digest=pre["proof_digest"])
    receipt["operation_id"] = "op-attacker"
    receipt["receipt_digest"] = sha256_digest(_receipt_payload(receipt))

    with pytest.raises(
        ExecutionReceiptError,
        match="EXECUTION_RECEIPT_OPERATION_ID_MISMATCH",
    ):
        SandCloudExecutionReceiptAdapter.adapt(
            operation_id="op-r4",
            pre_proof_digest=pre["proof_digest"],
            receipt=receipt,
            receipt_verifier=lambda item: True,
        )


def test_receipt_pre_proof_transplant_fails_closed() -> None:
    _, pre = _pre()
    other_pre_digest = sha256_digest({"other": "pre"})
    receipt = _receipt(provider="sandcloud", pre_proof_digest=other_pre_digest)

    with pytest.raises(
        ExecutionReceiptError,
        match="EXECUTION_RECEIPT_PRE_PROOF_DIGEST_MISMATCH",
    ):
        SandCloudExecutionReceiptAdapter.adapt(
            operation_id="op-r4",
            pre_proof_digest=pre["proof_digest"],
            receipt=receipt,
            receipt_verifier=lambda item: True,
        )


def test_tampered_receipt_digest_fails_closed() -> None:
    _, pre = _pre()
    receipt = _receipt(provider="sandcloud", pre_proof_digest=pre["proof_digest"])
    receipt["result_digest"] = sha256_digest({"tampered": True})

    with pytest.raises(ExecutionReceiptError, match="EXECUTION_RECEIPT_DIGEST_MISMATCH"):
        SandCloudExecutionReceiptAdapter.adapt(
            operation_id="op-r4",
            pre_proof_digest=pre["proof_digest"],
            receipt=receipt,
            receipt_verifier=lambda item: True,
        )


def test_untrusted_or_broken_receipt_verifier_fails_closed() -> None:
    _, pre = _pre()
    receipt = _receipt(provider="sandcloud", pre_proof_digest=pre["proof_digest"])

    with pytest.raises(ExecutionReceiptError, match="UNTRUSTED_EXECUTION_RECEIPT"):
        SandCloudExecutionReceiptAdapter.adapt(
            operation_id="op-r4",
            pre_proof_digest=pre["proof_digest"],
            receipt=receipt,
            receipt_verifier=lambda item: False,
        )

    def broken_verifier(item: object) -> bool:
        raise RuntimeError("receipt backend unavailable")

    with pytest.raises(
        ExecutionReceiptError,
        match="EXECUTION_RECEIPT_VERIFICATION_ERROR",
    ):
        SandCloudExecutionReceiptAdapter.adapt(
            operation_id="op-r4",
            pre_proof_digest=pre["proof_digest"],
            receipt=receipt,
            receipt_verifier=broken_verifier,
        )


def test_provider_mismatch_fails_closed() -> None:
    _, pre = _pre()
    receipt = _receipt(provider="caser", pre_proof_digest=pre["proof_digest"])

    with pytest.raises(
        ExecutionReceiptError,
        match="EXECUTION_RECEIPT_PROVIDER_MISMATCH",
    ):
        SandCloudExecutionReceiptAdapter.adapt(
            operation_id="op-r4",
            pre_proof_digest=pre["proof_digest"],
            receipt=receipt,
            receipt_verifier=lambda item: True,
        )


def test_r3_trust_verifier_rebinds_receipt_to_exact_final_context() -> None:
    pre_items, pre = _pre()
    receipt = _receipt(provider="sandcloud", pre_proof_digest=pre["proof_digest"])
    execution = SandCloudExecutionReceiptAdapter.adapt(
        operation_id="op-r4",
        pre_proof_digest=pre["proof_digest"],
        receipt=receipt,
        receipt_verifier=lambda item: True,
    )
    final = build_final_proof(pre, execution)

    receipts = {receipt["receipt_digest"]: receipt}
    execution_trust = make_execution_receipt_trust_verifier(
        provider_id="sandcloud",
        receipt_resolver=lambda digest: receipts.get(digest),
        receipt_verifier=lambda item: True,
    )

    registry = ProviderTrustRegistry()
    for item in pre_items:
        registry.register(
            layer=item.layer,
            provider=item.provider,
            verifier=lambda envelope, context: True,
        )
    registry.register(
        layer=Layer.EXECUTION,
        provider="sandcloud",
        verifier=execution_trust,
    )

    result = verify_proof_trust(final, registry)
    assert result.trusted is True
    assert result.reason_codes == ()


def test_r3_trust_verifier_rejects_missing_authoritative_receipt() -> None:
    pre_items, pre = _pre()
    receipt = _receipt(provider="sandcloud", pre_proof_digest=pre["proof_digest"])
    execution = SandCloudExecutionReceiptAdapter.adapt(
        operation_id="op-r4",
        pre_proof_digest=pre["proof_digest"],
        receipt=receipt,
        receipt_verifier=lambda item: True,
    )
    final = build_final_proof(pre, execution)

    registry = ProviderTrustRegistry()
    for item in pre_items:
        registry.register(
            layer=item.layer,
            provider=item.provider,
            verifier=lambda envelope, context: True,
        )
    registry.register(
        layer=Layer.EXECUTION,
        provider="sandcloud",
        verifier=make_execution_receipt_trust_verifier(
            provider_id="sandcloud",
            receipt_resolver=lambda digest: None,
            receipt_verifier=lambda item: True,
        ),
    )

    result = verify_proof_trust(final, registry)
    assert result.trusted is False
    assert "UNTRUSTED_PROVIDER_EVIDENCE:execution:sandcloud" in result.reason_codes


def test_r3_trust_verifier_rejects_receipt_bound_to_other_pre() -> None:
    pre_items, pre = _pre()
    receipt = _receipt(provider="sandcloud", pre_proof_digest=pre["proof_digest"])
    execution = SandCloudExecutionReceiptAdapter.adapt(
        operation_id="op-r4",
        pre_proof_digest=pre["proof_digest"],
        receipt=receipt,
        receipt_verifier=lambda item: True,
    )
    final = build_final_proof(pre, execution)

    other = dict(receipt)
    other["pre_proof_digest"] = sha256_digest({"other": "pre"})
    other["receipt_digest"] = sha256_digest(_receipt_payload(other))

    registry = ProviderTrustRegistry()
    for item in pre_items:
        registry.register(
            layer=item.layer,
            provider=item.provider,
            verifier=lambda envelope, context: True,
        )
    registry.register(
        layer=Layer.EXECUTION,
        provider="sandcloud",
        verifier=make_execution_receipt_trust_verifier(
            provider_id="sandcloud",
            receipt_resolver=lambda digest: other,
            receipt_verifier=lambda item: True,
        ),
    )

    result = verify_proof_trust(final, registry)
    assert result.trusted is False
    assert "UNTRUSTED_PROVIDER_EVIDENCE:execution:sandcloud" in result.reason_codes
