from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.trust import ProviderTrustRegistry, verify_proof_trust
from operationproof.verifier import verify_proof


def evidence(layer: Layer, *, verdict: Verdict = Verdict.PASS) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"test:{layer.value}",
        operation_id="op-1",
        decision="native-ok",
        verdict=verdict,
        subject_digest=sha256_digest({"subject": layer.value}),
        evidence_digest=sha256_digest({"evidence": layer.value, "verdict": verdict.value}),
        issued_at="2026-08-23T00:00:00+00:00",
    )


def registry_for(
    items: list[EvidenceEnvelope],
    *,
    overrides: dict[tuple[str, str], object] | None = None,
) -> ProviderTrustRegistry:
    registry = ProviderTrustRegistry()
    overrides = overrides or {}
    for item in items:
        key = (item.layer.value, item.provider)
        override = overrides.get(key)
        if callable(override):
            verifier = override
        else:
            expected_digest = item.evidence_digest
            verifier = lambda envelope, context, expected=expected_digest: (
                envelope.get("evidence_digest") == expected
            )
        registry.register(layer=item.layer, provider=item.provider, verifier=verifier)
    return registry


def test_verified_pre_proof_is_trusted_when_all_providers_verify() -> None:
    items = [evidence(layer) for layer in PRE_LAYERS]
    proof = build_pre_proof("op-1", items)
    result = verify_proof_trust(proof, registry_for(items))
    assert result.trusted is True
    assert result.reason_codes == ()


def test_unregistered_provider_fails_closed() -> None:
    items = [evidence(layer) for layer in PRE_LAYERS]
    registry = registry_for(items[:-1])
    proof = build_pre_proof("op-1", items)
    result = verify_proof_trust(proof, registry)
    assert result.trusted is False
    assert "UNREGISTERED_PROVIDER:resource:test:resource" in result.reason_codes


def test_provider_verifier_false_fails_closed() -> None:
    items = [evidence(layer) for layer in PRE_LAYERS]
    key = (Layer.INTENT.value, "test:intent")
    registry = registry_for(items, overrides={key: lambda envelope, context: False})
    proof = build_pre_proof("op-1", items)
    result = verify_proof_trust(proof, registry)
    assert result.trusted is False
    assert "UNTRUSTED_PROVIDER_EVIDENCE:intent:test:intent" in result.reason_codes


def test_provider_verifier_exception_fails_closed() -> None:
    items = [evidence(layer) for layer in PRE_LAYERS]

    def broken_verifier(envelope: object, context: object) -> bool:
        raise RuntimeError("provider unavailable")

    key = (Layer.CONTINUITY.value, "test:continuity")
    registry = registry_for(items, overrides={key: broken_verifier})
    proof = build_pre_proof("op-1", items)
    result = verify_proof_trust(proof, registry)
    assert result.trusted is False
    assert (
        "PROVIDER_TRUST_VERIFIER_ERROR:continuity:test:continuity"
        in result.reason_codes
    )


def test_duplicate_registry_entry_cannot_silently_replace_verifier() -> None:
    registry = ProviderTrustRegistry()
    registry.register(
        layer=Layer.IDENTITY,
        provider="issuer-a",
        verifier=lambda envelope, context: True,
    )

    try:
        registry.register(
            layer=Layer.IDENTITY,
            provider="issuer-a",
            verifier=lambda envelope, context: True,
        )
    except ValueError as exc:
        assert str(exc) == "DUPLICATE_PROVIDER_TRUST_ENTRY"
    else:
        raise AssertionError("duplicate trust registration must fail closed")


def test_structurally_valid_forged_evidence_is_rejected_by_provider_trust() -> None:
    items = [evidence(layer) for layer in PRE_LAYERS]
    registry = registry_for(items)
    proof = build_pre_proof("op-1", items)

    proof["evidence"][0]["evidence_digest"] = sha256_digest({"forged": "identity"})
    proof["proof_digest"] = sha256_digest(
        {key: value for key, value in proof.items() if key != "proof_digest"}
    )

    assert verify_proof(proof).valid is True
    trusted = verify_proof_trust(proof, registry)
    assert trusted.trusted is False
    assert "UNTRUSTED_PROVIDER_EVIDENCE:identity:test:identity" in trusted.reason_codes


def test_rejected_proof_is_never_promoted_by_provider_trust() -> None:
    items = [evidence(layer) for layer in PRE_LAYERS]
    items[2] = evidence(Layer.INTENT, verdict=Verdict.FAIL)
    proof = build_pre_proof("op-1", items)
    result = verify_proof_trust(proof, registry_for(items))
    assert result.trusted is False
    assert result.reason_codes == ("PROOF_NOT_VERIFIED",)


def test_final_proof_recursively_requires_pre_and_execution_provider_trust() -> None:
    pre_items = [evidence(layer) for layer in PRE_LAYERS]
    execution = evidence(Layer.EXECUTION)
    pre = build_pre_proof("op-1", pre_items)
    final = build_final_proof(pre, execution)

    registry = registry_for(pre_items + [execution])
    assert verify_proof_trust(final, registry).trusted is True

    incomplete_registry = registry_for(pre_items)
    result = verify_proof_trust(final, incomplete_registry)
    assert result.trusted is False
    assert "UNREGISTERED_PROVIDER:execution:test:execution" in result.reason_codes


def test_execution_verifier_receives_exact_final_pre_proof_context() -> None:
    pre_items = [evidence(layer) for layer in PRE_LAYERS]
    execution = evidence(Layer.EXECUTION)
    pre = build_pre_proof("op-1", pre_items)
    final = build_final_proof(pre, execution)

    key = (Layer.EXECUTION.value, "test:execution")

    def execution_verifier(envelope: object, context: object) -> bool:
        return (
            getattr(context, "root_phase", None) == "FINAL"
            and getattr(context, "evidence_phase", None) == "FINAL"
            and getattr(context, "operation_id", None) == "op-1"
            and getattr(context, "pre_proof_digest", None) == pre["proof_digest"]
            and getattr(context, "proof_digest", None) == final["proof_digest"]
        )

    registry = registry_for(
        pre_items + [execution],
        overrides={key: execution_verifier},
    )
    assert verify_proof_trust(final, registry).trusted is True


def test_integrity_failure_precedes_provider_trust() -> None:
    items = [evidence(layer) for layer in PRE_LAYERS]
    proof = build_pre_proof("op-1", items)
    proof["operation_id"] = "tampered"
    result = verify_proof_trust(proof, registry_for(items))
    assert result.trusted is False
    assert "PROOF_INTEGRITY_INVALID" in result.reason_codes
