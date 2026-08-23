import pytest

from operationproof.adapters.caser import CaserExecutionAdapter, CaserExecutionError
from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.execution import verify_execution_receipt
from operationproof.trust import ProviderTrustRegistry, verify_proof_trust
from operationproof.verifier import verify_proof


def pre_evidence(layer: Layer) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"test:{layer.value}",
        operation_id="op-1",
        decision="native-ok",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": layer.value}),
        evidence_digest=sha256_digest({"evidence": layer.value}),
        issued_at="2026-08-23T00:00:00+00:00",
    )


def verified_pre() -> tuple[dict[str, object], list[EvidenceEnvelope]]:
    items = [pre_evidence(layer) for layer in PRE_LAYERS]
    return build_pre_proof("op-1", items), items


def native_receipt() -> dict[str, object]:
    return {
        "schemaVersion": "execution-receipt/v1",
        "operationId": "op-1",
        "instanceId": "receipt-test-1",
        "contentIdentity": sha256_digest({"native": "receipt-1"}),
    }


def native_verification(
    receipt: dict[str, object],
    *,
    outcome_verified: bool = False,
    outcome: str | None = None,
    post_state_verified: bool = False,
    effect: str = "READ_ONLY",
    status: str = "PASS",
) -> dict[str, object]:
    checks: list[dict[str, object]] = [
        {
            "check": "receipt-schema",
            "status": "PASS",
            "observed": "execution-receipt/v1",
        },
        {
            "check": "content-identity",
            "status": "PASS",
            "observed": {
                "claimed": receipt["contentIdentity"],
                "calculated": receipt["contentIdentity"],
            },
        },
    ]
    if effect == "READ_ONLY":
        checks.append(
            {"check": "read-only-effect", "status": "PASS", "observed": "READ_ONLY"}
        )
    else:
        checks.append({"check": "effect-class", "status": "PASS", "observed": effect})
    if outcome_verified and outcome is not None:
        checks.append({"check": "execution-outcome", "status": "PASS", "observed": outcome})
    if post_state_verified:
        checks.append(
            {"check": "provider-post-state", "status": "PASS", "observed": "VERIFIED"}
        )

    verification: dict[str, object] = {
        "schemaVersion": "verification-result/v1",
        "instanceId": "verification-test-1",
        "verifierIdentity": "caser-independent-verifier/v0.1",
        "verifiedAt": "2026-08-23T00:01:00+00:00",
        "verificationStrength": "V2" if not outcome_verified else "V3",
        "verificationClass": "INDEPENDENT_CODE_PATH",
        "verificationScope": "EXECUTION_EVIDENCE_INTEGRITY",
        "receipt": {
            "contentIdentity": receipt["contentIdentity"],
            "operationId": receipt["operationId"],
            "instanceId": receipt["instanceId"],
        },
        "runnerIndependent": True,
        "checks": checks,
        "status": status,
        "claims": {
            "receiptIntegrityVerified": True,
            "executionOutcomeIndependentlyVerified": outcome_verified,
            "providerPostStateVerified": post_state_verified,
        },
        "contentIdentity": sha256_digest(
            {
                "native": "verification-1",
                "outcome_verified": outcome_verified,
                "outcome": outcome,
                "post_state": post_state_verified,
                "effect": effect,
                "status": status,
            }
        ),
    }
    if outcome is not None:
        verification["executionOutcome"] = outcome
    return verification


def trusted_binding(
    pre: dict[str, object],
    receipt: dict[str, object],
    verification: dict[str, object],
) -> dict[str, object]:
    payload = {
        "schema": "operationproof.caser-execution-binding.v1",
        "operation_id": pre["operation_id"],
        "pre_proof_digest": pre["proof_digest"],
        "receipt_content_identity": receipt["contentIdentity"],
        "verification_content_identity": verification["contentIdentity"],
        "execution_instance_id": receipt["instanceId"],
        "issued_at": "2026-08-23T00:02:00+00:00",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }
    return {
        **payload,
        "binding_digest": sha256_digest(payload),
        "attestation": "trusted-test-binding",
    }


def accept_binding(binding: object) -> bool:
    return isinstance(binding, dict) and binding.get("attestation") == "trusted-test-binding"


def adapt(
    pre: dict[str, object],
    receipt: dict[str, object],
    verification: dict[str, object],
) -> EvidenceEnvelope:
    return CaserExecutionAdapter.adapt(
        pre_proof=pre,
        receipt=receipt,
        verification=verification,
        binding=trusted_binding(pre, receipt, verification),
        binding_verifier=accept_binding,
    )


def test_existing_caser_v2_maps_to_unknown_not_pass() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(receipt)

    execution = adapt(pre, receipt, verification)
    assert execution.verdict == Verdict.UNKNOWN
    assert execution.decision == "EXECUTION_INSUFFICIENT"

    final = build_final_proof(pre, execution)
    assert final["decision"] == "REJECTED"
    assert "LAYER_UNKNOWN:execution" in final["reason_codes"]
    assert verify_proof(final).valid is True


def test_verified_read_only_success_can_complete_final_proof() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(
        receipt,
        outcome_verified=True,
        outcome="SUCCEEDED",
    )

    execution = adapt(pre, receipt, verification)
    assert execution.verdict == Verdict.PASS
    normalized = execution.metadata["execution_receipt"]
    assert verify_execution_receipt(normalized).valid is True
    assert normalized["pre_proof_digest"] == pre["proof_digest"]

    final = build_final_proof(pre, execution)
    assert final["decision"] == "VERIFIED"
    assert verify_proof(final).valid is True


def test_mutating_success_without_provider_post_state_is_unknown() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(
        receipt,
        outcome_verified=True,
        outcome="SUCCEEDED",
        effect="MUTATING",
        post_state_verified=False,
    )

    execution = adapt(pre, receipt, verification)
    assert execution.verdict == Verdict.UNKNOWN
    assert execution.metadata["execution_receipt"]["effect_class"] == "MUTATING"


def test_mutating_success_with_provider_post_state_can_pass() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(
        receipt,
        outcome_verified=True,
        outcome="SUCCEEDED",
        effect="MUTATING",
        post_state_verified=True,
    )

    execution = adapt(pre, receipt, verification)
    assert execution.verdict == Verdict.PASS


def test_verified_failed_outcome_maps_to_fail() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(
        receipt,
        outcome_verified=True,
        outcome="FAILED",
    )

    execution = adapt(pre, receipt, verification)
    assert execution.verdict == Verdict.FAIL
    assert execution.decision == "EXECUTION_FAILED"


def test_outcome_claim_without_independent_check_fails_closed() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(
        receipt,
        outcome_verified=True,
        outcome="SUCCEEDED",
    )
    verification["checks"] = [
        item
        for item in verification["checks"]  # type: ignore[union-attr]
        if item.get("check") != "execution-outcome"
    ]

    with pytest.raises(CaserExecutionError, match="CASER_REQUIRED_CHECK_NOT_PASS:execution-outcome"):
        adapt(pre, receipt, verification)


def test_post_state_claim_without_independent_check_fails_closed() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(
        receipt,
        outcome_verified=True,
        outcome="SUCCEEDED",
        effect="MUTATING",
        post_state_verified=True,
    )
    verification["checks"] = [
        item
        for item in verification["checks"]  # type: ignore[union-attr]
        if item.get("check") != "provider-post-state"
    ]

    with pytest.raises(CaserExecutionError, match="CASER_REQUIRED_CHECK_NOT_PASS:provider-post-state"):
        adapt(pre, receipt, verification)


def test_binding_must_match_exact_pre_proof_digest() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(receipt)
    binding = trusted_binding(pre, receipt, verification)
    binding["pre_proof_digest"] = sha256_digest({"wrong": "pre"})
    binding["binding_digest"] = sha256_digest(
        {key: value for key, value in binding.items() if key not in {"binding_digest", "attestation"}}
    )

    with pytest.raises(CaserExecutionError, match="CASER_BINDING_MISMATCH:pre_proof_digest"):
        CaserExecutionAdapter.adapt(
            pre_proof=pre,
            receipt=receipt,
            verification=verification,
            binding=binding,
            binding_verifier=accept_binding,
        )


def test_verification_receipt_reference_mismatch_fails_closed() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(receipt)
    verification["receipt"]["operationId"] = "op-other"  # type: ignore[index]

    with pytest.raises(CaserExecutionError, match="CASER_VERIFICATION_OPERATION_MISMATCH"):
        adapt(pre, receipt, verification)


def test_binding_verifier_exception_fails_closed() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(receipt)
    binding = trusted_binding(pre, receipt, verification)

    def broken_verifier(value: object) -> bool:
        raise RuntimeError("trust service unavailable")

    with pytest.raises(CaserExecutionError, match="CASER_BINDING_VERIFICATION_ERROR"):
        CaserExecutionAdapter.adapt(
            pre_proof=pre,
            receipt=receipt,
            verification=verification,
            binding=binding,
            binding_verifier=broken_verifier,
        )


def test_execution_receipt_digest_tampering_is_detected() -> None:
    pre, _ = verified_pre()
    receipt = native_receipt()
    verification = native_verification(
        receipt,
        outcome_verified=True,
        outcome="SUCCEEDED",
    )
    execution = adapt(pre, receipt, verification)
    normalized = dict(execution.metadata["execution_receipt"])
    normalized["execution_instance_id"] = "tampered"

    result = verify_execution_receipt(normalized)
    assert result.valid is False
    assert "EXECUTION_RECEIPT_DIGEST_MISMATCH" in result.reason_codes


def test_r3_provider_trust_can_bind_caser_execution_to_exact_pre() -> None:
    pre, pre_items = verified_pre()
    receipt = native_receipt()
    verification = native_verification(
        receipt,
        outcome_verified=True,
        outcome="SUCCEEDED",
    )
    binding = trusted_binding(pre, receipt, verification)
    execution = CaserExecutionAdapter.adapt(
        pre_proof=pre,
        receipt=receipt,
        verification=verification,
        binding=binding,
        binding_verifier=accept_binding,
    )
    final = build_final_proof(pre, execution)

    registry = ProviderTrustRegistry()
    for item in pre_items:
        registry.register(
            layer=item.layer,
            provider=item.provider,
            verifier=lambda envelope, context: True,
        )

    expected_binding_digest = binding["binding_digest"]

    def caser_verifier(envelope: object, context: object) -> bool:
        if not isinstance(envelope, dict):
            return False
        metadata = envelope.get("metadata")
        if not isinstance(metadata, dict):
            return False
        normalized = metadata.get("execution_receipt")
        return (
            isinstance(normalized, dict)
            and getattr(context, "root_phase", None) == "FINAL"
            and getattr(context, "pre_proof_digest", None) == pre["proof_digest"]
            and normalized.get("pre_proof_digest") == pre["proof_digest"]
            and metadata.get("binding_digest") == expected_binding_digest
        )

    registry.register(layer=Layer.EXECUTION, provider="caser", verifier=caser_verifier)
    result = verify_proof_trust(final, registry)
    assert result.trusted is True
