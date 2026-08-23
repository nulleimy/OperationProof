from __future__ import annotations

from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.trust import (
    DIRECT_VERIFICATION_STAGE,
    EMBEDDED_PRE_OF_FINAL_STAGE,
    ProviderTrustRegistry,
    verify_proof_trust,
)


def _evidence(layer: Layer) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"stage-{layer.value}",
        operation_id="op-stage",
        decision="PASS",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": layer.value}),
        evidence_digest=sha256_digest({"evidence": layer.value}),
        issued_at="2099-01-01T00:00:00.000+00:00",
        metadata={},
    )


def test_embedded_pre_keeps_pre_context_but_gets_internal_post_execution_stage() -> None:
    pre_items = [_evidence(layer) for layer in PRE_LAYERS]
    execution = _evidence(Layer.EXECUTION)
    pre = build_pre_proof("op-stage", pre_items)
    final = build_final_proof(pre, execution)
    observed: list[object] = []

    def verifier(_item: object, context: object) -> bool:
        observed.append(context)
        return True

    registry = ProviderTrustRegistry()
    for item in pre_items + [execution]:
        registry.register(layer=item.layer, provider=item.provider, verifier=verifier)

    assert verify_proof_trust(pre, registry).trusted is True
    direct = list(observed)
    observed.clear()
    assert all(getattr(ctx, "verification_stage", None) == DIRECT_VERIFICATION_STAGE for ctx in direct)

    assert verify_proof_trust(final, registry).trusted is True
    embedded = [ctx for ctx in observed if getattr(ctx, "root_phase", None) == "PRE"]
    outer = [ctx for ctx in observed if getattr(ctx, "root_phase", None) == "FINAL"]

    assert len(embedded) == len(PRE_LAYERS)
    assert all(getattr(ctx, "evidence_phase", None) == "PRE" for ctx in embedded)
    assert all(getattr(ctx, "proof_digest", None) == pre["proof_digest"] for ctx in embedded)
    assert all(getattr(ctx, "pre_proof_digest", None) is None for ctx in embedded)
    assert all(
        getattr(ctx, "verification_stage", None) == EMBEDDED_PRE_OF_FINAL_STAGE
        for ctx in embedded
    )
    assert len(outer) == 1
    assert getattr(outer[0], "verification_stage", None) == DIRECT_VERIFICATION_STAGE
    assert getattr(outer[0], "proof_digest", None) == final["proof_digest"]
