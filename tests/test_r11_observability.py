from __future__ import annotations

from collections.abc import Mapping

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


def test_observability_event_is_tamper_evident_and_deterministic() -> None:
    kwargs = {
        "event_type": operationproof.ObservabilityEventType.GATEWAY_FORWARD_ALLOWED,
        "occurred_at": "2026-08-24T01:00:00+00:00",
        "operation_id": "op-observe",
        "subject_digest": sha256_digest({"subject": 1}),
        "artifact_digest": sha256_digest({"artifact": 1}),
        "outcome": "ALLOWED",
        "reason_codes": (),
        "attributes": {"upstream_id": "service-a"},
    }
    first = operationproof.build_observability_event(**kwargs)
    second = operationproof.build_observability_event(**kwargs)

    valid, reasons = operationproof.verify_observability_event(first)
    assert first == second
    assert valid is True
    assert reasons == ()

    first["attributes"]["upstream_id"] = "tampered"
    valid, reasons = operationproof.verify_observability_event(first)
    assert valid is False
    assert "OBSERVABILITY_EVENT_DIGEST_MISMATCH" in reasons


def test_memory_sink_detaches_caller_owned_event() -> None:
    sink = operationproof.MemoryTelemetrySink(max_events=2)
    event = operationproof.build_observability_event(
        event_type=operationproof.ObservabilityEventType.ATTESTATION_CREATED,
        occurred_at="2026-08-24T01:00:00+00:00",
        operation_id="op-observe",
        attestation_digest=sha256_digest({"attestation": 1}),
        outcome="CREATED",
        attributes={"nested": {"value": "before"}},
    )

    result = operationproof.emit_observability_event(sink, event)
    event["attributes"]["nested"]["value"] = "after"
    stored = sink.snapshot()[0]

    assert result.emitted is True
    assert stored["attributes"]["nested"]["value"] == "before"


class _FailingSink(operationproof.TelemetrySink):
    def emit(self, event: Mapping[str, object]) -> None:
        raise RuntimeError("sink unavailable")


def test_sink_failure_cannot_change_governed_assessment() -> None:
    proof = _proof()
    baseline = operationproof.assess_proof(proof, registry=_registry())
    observed, emit_result = operationproof.assess_proof_observed(
        proof,
        registry=_registry(),
        sink=_FailingSink(),
        occurred_at="2026-08-24T01:02:00+00:00",
    )

    assert baseline.accepted is True
    assert observed == baseline
    assert emit_result.emitted is False
    assert emit_result.reason_codes == ("TELEMETRY_SINK_FAILED",)


def test_invalid_event_is_not_sent_to_sink() -> None:
    sink = operationproof.MemoryTelemetrySink()
    event = operationproof.build_observability_event(
        event_type=operationproof.ObservabilityEventType.PROOF_ASSESSED,
        occurred_at="2026-08-24T01:00:00+00:00",
        operation_id="op-observe",
        outcome="ACCEPTED",
    )
    event["operation_id"] = "tampered"

    result = operationproof.emit_observability_event(sink, event)

    assert result.emitted is False
    assert result.reason_codes == ("EVENT:OBSERVABILITY_EVENT_DIGEST_MISMATCH",)
    assert sink.snapshot() == ()
