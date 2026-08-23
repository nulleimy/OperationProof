from datetime import UTC, datetime

import pytest

from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.subject import OperationSubject
from operationproof.subject_binding import (
    SubjectBindingError,
    bind_evidence_to_subject,
    make_subject_bound_trust_verifier,
)
from operationproof.trust import ProviderTrustRegistry, verify_proof_trust
from operationproof.verifier import verify_proof

NOW = datetime(2026, 8, 23, 19, 45, tzinfo=UTC)


def canonical_subject() -> OperationSubject:
    return OperationSubject(
        operation_id="op-r6-binding",
        actor_digest=sha256_digest({"actor": "agent-7"}),
        intent_digest=sha256_digest({"intent": "deploy", "payload": "artifact-9"}),
        target_digest=sha256_digest({"target": "service-a"}),
        state_digest=sha256_digest({"state": "rev-41"}),
    )


def native_evidence(layer: Layer) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"native:{layer.value}",
        operation_id="op-r6-binding",
        decision="native-pass",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest(
            {"provider_native_subject": layer.value, "revision": 1}
        ),
        evidence_digest=sha256_digest({"native_evidence": layer.value}),
        issued_at="2026-08-23T19:40:00+00:00",
        expires_at="2026-08-23T20:30:00+00:00",
        metadata={"native_marker": layer.value},
    )


def subject_binding(
    envelope: EvidenceEnvelope,
    subject: OperationSubject,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "operationproof.subject-binding.v1",
        "operation_id": envelope.operation_id,
        "layer": envelope.layer.value,
        "provider": envelope.provider,
        "native_envelope_digest": sha256_digest(envelope.to_dict()),
        "native_subject_digest": envelope.subject_digest,
        "canonical_subject_digest": subject.digest,
        "issued_at": "2026-08-23T19:44:00+00:00",
        "expires_at": "2026-08-23T20:00:00+00:00",
    }
    return {**payload, "binding_digest": sha256_digest(payload)}


def accepts_binding(binding: object) -> bool:
    return isinstance(binding, dict) and binding.get("schema") == "operationproof.subject-binding.v1"


def test_binding_requires_external_attestation_and_exact_native_envelope() -> None:
    subject = canonical_subject()
    native = native_evidence(Layer.IDENTITY)
    binding = subject_binding(native, subject)

    bound = bind_evidence_to_subject(
        native,
        subject=subject,
        binding=binding,
        binding_verifier=accepts_binding,
        now=NOW,
    )

    assert native.subject_digest != subject.digest
    assert bound.subject_digest == subject.digest
    marker = bound.metadata["operationproof_subject_binding"]
    assert marker["native_subject_digest"] == native.subject_digest
    assert marker["native_envelope_digest"] == sha256_digest(native.to_dict())


def test_binding_for_another_native_envelope_fails_closed() -> None:
    subject = canonical_subject()
    identity = native_evidence(Layer.IDENTITY)
    authorization = native_evidence(Layer.AUTHORIZATION)
    binding = subject_binding(identity, subject)

    with pytest.raises(
        SubjectBindingError,
        match="SUBJECT_BINDING_MISMATCH:layer",
    ):
        bind_evidence_to_subject(
            authorization,
            subject=subject,
            binding=binding,
            binding_verifier=accepts_binding,
            now=NOW,
        )


def test_untrusted_subject_binding_cannot_relabel_native_evidence() -> None:
    subject = canonical_subject()
    native = native_evidence(Layer.IDENTITY)

    with pytest.raises(SubjectBindingError, match="UNTRUSTED_SUBJECT_BINDING"):
        bind_evidence_to_subject(
            native,
            subject=subject,
            binding=subject_binding(native, subject),
            binding_verifier=lambda binding: False,
            now=NOW,
        )


def test_subject_bound_trust_wrapper_reconstructs_exact_native_envelope() -> None:
    subject = canonical_subject()
    native = native_evidence(Layer.AUTHORIZATION)
    binding = subject_binding(native, subject)
    bound = bind_evidence_to_subject(
        native,
        subject=subject,
        binding=binding,
        binding_verifier=accepts_binding,
        now=NOW,
    )

    bindings = {str(binding["binding_digest"]): binding}

    def native_verifier(envelope: object, context: object) -> bool:
        return isinstance(envelope, dict) and envelope == native.to_dict()

    wrapper = make_subject_bound_trust_verifier(
        native_verifier=native_verifier,
        binding_resolver=lambda digest: bindings.get(digest),
        binding_verifier=accepts_binding,
        clock=lambda: NOW,
    )

    from operationproof.trust import TrustVerificationContext

    context = TrustVerificationContext(
        root_phase="PRE",
        evidence_phase="PRE",
        operation_id=subject.operation_id,
        proof_digest=sha256_digest({"proof": "test"}),
        pre_proof_digest=None,
        evidence_index=0,
    )
    assert wrapper(bound.to_dict(), context) is True


def test_subject_binding_wrapper_rejects_authoritative_binding_drift() -> None:
    subject = canonical_subject()
    native = native_evidence(Layer.AUTHORIZATION)
    binding = subject_binding(native, subject)
    bound = bind_evidence_to_subject(
        native,
        subject=subject,
        binding=binding,
        binding_verifier=accepts_binding,
        now=NOW,
    )
    drifted = dict(binding)
    drifted["canonical_subject_digest"] = sha256_digest({"subject": "other"})

    wrapper = make_subject_bound_trust_verifier(
        native_verifier=lambda envelope, context: envelope == native.to_dict(),
        binding_resolver=lambda digest: drifted,
        binding_verifier=accepts_binding,
        clock=lambda: NOW,
    )

    from operationproof.trust import TrustVerificationContext

    context = TrustVerificationContext(
        root_phase="PRE",
        evidence_phase="PRE",
        operation_id=subject.operation_id,
        proof_digest=sha256_digest({"proof": "test"}),
        pre_proof_digest=None,
        evidence_index=0,
    )
    assert wrapper(bound.to_dict(), context) is False


def test_all_layers_can_compose_one_subject_without_weakening_native_trust() -> None:
    subject = canonical_subject()
    natives = {layer: native_evidence(layer) for layer in (*PRE_LAYERS, Layer.EXECUTION)}
    bindings = {
        layer: subject_binding(native, subject)
        for layer, native in natives.items()
    }
    bound = {
        layer: bind_evidence_to_subject(
            native,
            subject=subject,
            binding=bindings[layer],
            binding_verifier=accepts_binding,
            now=NOW,
        )
        for layer, native in natives.items()
    }

    pre = build_pre_proof(
        subject.operation_id,
        [bound[layer] for layer in PRE_LAYERS],
        subject=subject,
    )
    final = build_final_proof(pre, bound[Layer.EXECUTION])

    assert pre["decision"] == "VERIFIED"
    assert final["decision"] == "VERIFIED"
    assert verify_proof(final).valid is True

    registry = ProviderTrustRegistry()
    for layer, native in natives.items():
        binding = bindings[layer]
        resolver_map = {str(binding["binding_digest"]): binding}
        native_dict = native.to_dict()
        registry.register(
            layer=layer,
            provider=native.provider,
            verifier=make_subject_bound_trust_verifier(
                native_verifier=(
                    lambda envelope, context, expected=native_dict: envelope == expected
                ),
                binding_resolver=(
                    lambda digest, values=resolver_map: values.get(digest)
                ),
                binding_verifier=accepts_binding,
                clock=lambda: NOW,
            ),
        )

    assert verify_proof_trust(final, registry).trusted is True
