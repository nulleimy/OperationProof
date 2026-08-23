from __future__ import annotations

import asyncio
from dataclasses import asdict, fields

from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.trust import (
    DIRECT_VERIFICATION_STAGE,
    EMBEDDED_PRE_OF_FINAL_STAGE,
    ProviderTrustRegistry,
    TrustVerificationContext,
    _current_verification_stage,
    verify_proof_trust,
)

_CONTEXT_FIELDS = (
    "root_phase",
    "evidence_phase",
    "operation_id",
    "proof_digest",
    "pre_proof_digest",
    "evidence_index",
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


def test_stage_is_callback_scoped_without_changing_legacy_context_fields() -> None:
    pre_items = [_evidence(layer) for layer in PRE_LAYERS]
    execution = _evidence(Layer.EXECUTION)
    pre = build_pre_proof("op-stage", pre_items)
    final = build_final_proof(pre, execution)

    observed_contexts: list[TrustVerificationContext] = []
    observed_stages: list[tuple[str, str]] = []

    def verifier(_item: object, context: TrustVerificationContext) -> bool:
        observed_contexts.append(context)
        observed_stages.append((context.root_phase, _current_verification_stage()))
        return True

    registry = ProviderTrustRegistry()
    for item in pre_items + [execution]:
        registry.register(layer=item.layer, provider=item.provider, verifier=verifier)

    assert verify_proof_trust(pre, registry).trusted is True
    assert observed_stages == [("PRE", DIRECT_VERIFICATION_STAGE)] * len(PRE_LAYERS)

    for context in observed_contexts:
        assert tuple(field.name for field in fields(context)) == _CONTEXT_FIELDS
        assert tuple(asdict(context)) == _CONTEXT_FIELDS
        assert not hasattr(context, "verification_stage")

    observed_contexts.clear()
    observed_stages.clear()

    assert verify_proof_trust(final, registry).trusted is True

    embedded = [stage for phase, stage in observed_stages if phase == "PRE"]
    outer = [stage for phase, stage in observed_stages if phase == "FINAL"]
    assert embedded == [EMBEDDED_PRE_OF_FINAL_STAGE] * len(PRE_LAYERS)
    assert outer == [DIRECT_VERIFICATION_STAGE]

    embedded_contexts = [context for context in observed_contexts if context.root_phase == "PRE"]
    assert len(embedded_contexts) == len(PRE_LAYERS)
    assert all(context.evidence_phase == "PRE" for context in embedded_contexts)
    assert all(context.proof_digest == pre["proof_digest"] for context in embedded_contexts)
    assert all(context.pre_proof_digest is None for context in embedded_contexts)

    assert _current_verification_stage() == DIRECT_VERIFICATION_STAGE


def test_embedded_stage_is_revoked_in_inherited_asyncio_context() -> None:
    async def scenario() -> None:
        pre_items = [_evidence(layer) for layer in PRE_LAYERS]
        execution = _evidence(Layer.EXECUTION)
        pre = build_pre_proof("op-stage", pre_items)
        final = build_final_proof(pre, execution)
        child_tasks: list[asyncio.Task[None]] = []
        child_observed_stages: list[str] = []

        def verifier(_item: object, context: TrustVerificationContext) -> bool:
            if (
                context.root_phase == "PRE"
                and _current_verification_stage() == EMBEDDED_PRE_OF_FINAL_STAGE
                and not child_tasks
            ):

                async def observe_after_callback() -> None:
                    await asyncio.sleep(0)
                    child_observed_stages.append(_current_verification_stage())

                child_tasks.append(asyncio.create_task(observe_after_callback()))
            return True

        registry = ProviderTrustRegistry()
        for item in pre_items + [execution]:
            registry.register(layer=item.layer, provider=item.provider, verifier=verifier)

        result = verify_proof_trust(final, registry)
        assert result.trusted is True
        assert len(child_tasks) == 1

        await asyncio.gather(*child_tasks)
        assert child_observed_stages == [DIRECT_VERIFICATION_STAGE]

    asyncio.run(scenario())