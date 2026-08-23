from operationproof.builder import build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.trust import ProviderTrustRegistry, verify_proof_trust
from operationproof.verifier import verify_proof


def _evidence(layer: Layer) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"test:{layer.value}",
        operation_id="op-r3-1",
        decision="native-ok",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": layer.value}),
        evidence_digest=sha256_digest({"evidence": layer.value}),
        issued_at="2026-08-23T00:00:00+00:00",
    )


def _registry(items: list[EvidenceEnvelope]) -> ProviderTrustRegistry:
    registry = ProviderTrustRegistry()
    for item in items:
        registry.register(
            layer=item.layer,
            provider=item.provider,
            verifier=lambda envelope, context: True,
        )
    return registry


def test_pre_rejects_attacker_controlled_pre_proof_digest() -> None:
    items = [_evidence(layer) for layer in PRE_LAYERS]
    pre = build_pre_proof("op-r3-1", items)

    pre["pre_proof_digest"] = sha256_digest({"attacker": "controlled"})
    pre["proof_digest"] = sha256_digest(
        {key: value for key, value in pre.items() if key != "proof_digest"}
    )

    structural = verify_proof(pre)
    assert structural.valid is False
    assert "PRE_PROOF_DIGEST_FIELD_FORBIDDEN" in structural.reason_codes

    trusted = verify_proof_trust(pre, _registry(items))
    assert trusted.trusted is False
    assert "PROOF_INTEGRITY:PRE_PROOF_DIGEST_FIELD_FORBIDDEN" in trusted.reason_codes


def test_pre_rejects_embedded_pre_proof_field() -> None:
    items = [_evidence(layer) for layer in PRE_LAYERS]
    pre = build_pre_proof("op-r3-1", items)

    pre["pre_proof"] = {"attacker": "controlled"}
    pre["proof_digest"] = sha256_digest(
        {key: value for key, value in pre.items() if key != "proof_digest"}
    )

    structural = verify_proof(pre)
    assert structural.valid is False
    assert "PRE_PROOF_FIELD_FORBIDDEN" in structural.reason_codes
