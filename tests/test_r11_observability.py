from __future__ import annotations

from collections.abc import Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import operationproof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Verdict


def _proof(operation_id: str = "op-r11-observed") -> dict[str, object]:
    subject = operationproof.OperationSubject(
        operation_id=operation_id,
        actor_digest=sha256_digest({"actor": "observer"}),
        intent_digest=sha256_digest({"intent": "read"}),
        target_digest=sha256_digest({"target": "catalog"}),
        state_digest=sha256_digest({"state": "v1"}),
    )
    evidence = [
        EvidenceEnvelope(
            layer=layer,
            provider=f"observed:{layer.value}",
            operation_id=operation_id,
            decision="native-ok",
            verdict=Verdict.PASS,
            subject_digest=subject.digest,
            evidence_digest=sha256_digest({"layer": layer.value}),
            issued_at="2026-08-24T01:00:00+00:00",
            expires_at="2030-01-01T00:00:00+00:00",
        )
        for layer in PRE_LAYERS
    ]
    return operationproof.build_pre_proof(operation_id, evidence, subject=subject)


def _registry() -> operationproof.ProviderTrustRegistry:
    registry = operationproof.ProviderTrustRegistry()
    for layer in PRE_LAYERS:
        registry.register(
            layer=layer,
            provider=f"observed:{layer.value}",
            verifier=lambda _envelope, _context: True,
        )
    return registry


def _signing() -> tuple[
    operationproof.Ed25519AttestationSigner,
    operationproof.AttestationTrustRegistry,
]:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signer = operationproof.Ed25519AttestationSigner(
        key_id="telemetry-key",
        private_key=private_bytes,
    )
    registry = operationproof.AttestationTrustRegistry()
    registry.register_ed25519_public_key(key_id="telemetry-key", public_key=public_bytes)
    return signer, registry


def _event() -> dict[str, object]:
    return operationproof.build_observability_event(
        event_type=operationproof.ObservabilityEventType.GATEWAY_FORWARD_ALLOWED,
        occurred_at="2026-08-24T01:00:00+00:00",
        operation_id="op-observe",
        subject_digest=sha256_digest({"subject": 1}),
        artifact_digest=sha256_digest({"artifact": 1}),
        outcome="ALLOWED",
        reason_codes=(),
        attributes={"upstream_id": "service-a"},
    )


def test_canonical_event_is_deterministic_but_authenticity_requires_signature() -> None:
    first = _event()
    second = _event()
    valid, reasons = operationproof.verify_observability_event(first)

    assert first == second
    assert valid is True
    assert reasons == ()


def test_signed_event_rejects_payload_tamper_even_if_attacker_rehashes_all_digests() -> None:
    signer, registry = _signing()
    signed = operationproof.sign_observability_event(_event(), signer)
    signed["event"]["attributes"]["upstream_id"] = "attacker"
    signed["event"]["event_digest"] = sha256_digest(
        {
            key: value
            for key, value in signed["event"].items()
            if key != "event_digest"
        }
    )
    signed["event_digest"] = signed["event"]["event_digest"]
    signed["signed_event_digest"] = sha256_digest(
        {
            key: value
            for key, value in signed.items()
            if key != "signed_event_digest"
        }
    )

    result = operationproof.verify_signed_observability_event(signed, registry)

    assert result.valid is False
    assert result.trusted is False
    assert "OBSERVABILITY_SIGNATURE_INVALID" in result.reason_codes


def test_memory_sink_requires_trusted_signature_and_detaches_caller_event() -> None:
    signer, attestation_registry = _signing()
    sink = operationproof.MemoryTelemetrySink(attestation_registry, max_events=2)
    event = operationproof.build_observability_event(
        event_type=operationproof.ObservabilityEventType.ATTESTATION_CREATED,
        occurred_at="2026-08-24T01:00:00+00:00",
        operation_id="op-observe",
        attestation_digest=sha256_digest({"attestation": 1}),
        outcome="CREATED",
        attributes={"nested": {"value": "before"}},
    )

    result = operationproof.emit_observability_event(sink, event, signer=signer)
    event["attributes"]["nested"]["value"] = "after"
    stored = sink.snapshot()[0]
    verification = operationproof.verify_signed_observability_event(stored, attestation_registry)

    assert result.emitted is True
    assert stored["event"]["attributes"]["nested"]["value"] == "before"
    assert verification.valid is True
    assert verification.trusted is True


class _FailingSink(operationproof.TelemetrySink):
    def emit(self, signed_event: Mapping[str, object]) -> None:
        raise RuntimeError("sink unavailable")


def test_sink_failure_cannot_change_governed_assessment() -> None:
    signer, _attestation_registry = _signing()
    proof = _proof()
    baseline = operationproof.assess_proof(proof, registry=_registry())
    observed, emit_result = operationproof.assess_proof_observed(
        proof,
        registry=_registry(),
        sink=_FailingSink(),
        signer=signer,
        occurred_at="2026-08-24T01:02:00+00:00",
    )

    assert baseline.accepted is True
    assert observed == baseline
    assert emit_result.emitted is False
    assert emit_result.reason_codes == ("TELEMETRY_SINK_FAILED",)


def test_invalid_event_is_not_signed_or_sent_to_sink() -> None:
    signer, attestation_registry = _signing()
    sink = operationproof.MemoryTelemetrySink(attestation_registry)
    event = operationproof.build_observability_event(
        event_type=operationproof.ObservabilityEventType.PROOF_ASSESSED,
        occurred_at="2026-08-24T01:00:00+00:00",
        operation_id="op-observe",
        outcome="ACCEPTED",
    )
    event["operation_id"] = "tampered"

    result = operationproof.emit_observability_event(sink, event, signer=signer)

    assert result.emitted is False
    assert result.reason_codes == ("EVENT:OBSERVABILITY_EVENT_DIGEST_MISMATCH",)
    assert sink.snapshot() == ()


def test_long_attacker_controlled_integrity_reason_cannot_abort_observed_assessment() -> None:
    signer, attestation_registry = _signing()
    sink = operationproof.MemoryTelemetrySink(attestation_registry)
    proof = _proof()
    proof["x" * 300] = "unexpected"
    proof["proof_digest"] = sha256_digest(
        {key: value for key, value in proof.items() if key != "proof_digest"}
    )
    baseline = operationproof.assess_proof(proof, registry=_registry())

    observed, emit_result = operationproof.assess_proof_observed(
        proof,
        registry=_registry(),
        sink=sink,
        signer=signer,
        occurred_at="2026-08-24T01:03:00+00:00",
    )

    assert baseline.accepted is False
    assert observed == baseline
    assert emit_result.emitted is True
    stored_event = sink.snapshot()[0]["event"]
    assert any(code.startswith("REASON_DIGEST:sha256:") for code in stored_event["reason_codes"])
