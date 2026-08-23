from __future__ import annotations

from copy import deepcopy

import pytest

from operationproof.canonical import sha256_digest
from operationproof.conformance import (
    ConformanceScenario,
    ProviderConformanceCase,
    ProviderConformanceError,
    run_provider_conformance,
)
from operationproof.domain import EvidenceEnvelope, Layer, Verdict
from operationproof.provider import (
    ProviderAdapterContractError,
    ProviderAdapterManifest,
    ProviderAdapterRegistry,
    validate_adapter_output,
)


class FakeAdapterError(ValueError):
    pass


def manifest() -> ProviderAdapterManifest:
    return ProviderAdapterManifest(
        adapter_id="example.identity.v1",
        provider_id="example-idp",
        layer=Layer.IDENTITY,
        native_protocols=("example.identity-assertion.v1",),
    )


def envelope(operation_id: str = "op-r9") -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=Layer.IDENTITY,
        provider="example-idp",
        operation_id=operation_id,
        decision="IDENTITY_VERIFIED",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": operation_id}),
        evidence_digest=sha256_digest({"evidence": operation_id}),
        issued_at="2030-01-01T00:00:00+00:00",
        expires_at="2030-01-01T00:05:00+00:00",
        metadata={"adapter": "example.identity.v1"},
    )


def test_manifest_and_registry_are_exact_and_duplicate_safe() -> None:
    item = manifest()
    registry = ProviderAdapterRegistry()
    registry.register(item)

    assert registry.manifest_for(layer=Layer.IDENTITY, provider_id="example-idp") == item
    assert registry.manifest_for(layer="identity", provider_id="example-idp") == item
    assert registry.manifests() == (item,)
    assert item.to_dict()["contract"] == "operationproof.provider-adapter.v1"

    with pytest.raises(ProviderAdapterContractError, match="DUPLICATE_PROVIDER_ADAPTER"):
        registry.register(item)

    with pytest.raises(ProviderAdapterContractError, match="DUPLICATE_ADAPTER_ID"):
        registry.register(
            ProviderAdapterManifest(
                adapter_id=item.adapter_id,
                provider_id="other-idp",
                layer=Layer.IDENTITY,
                native_protocols=("other.v1",),
            )
        )


def test_manifest_rejects_weakened_or_ambiguous_contracts() -> None:
    with pytest.raises(ProviderAdapterContractError, match="DUPLICATE_NATIVE_PROTOCOL"):
        ProviderAdapterManifest(
            adapter_id="example.v1",
            provider_id="example",
            layer=Layer.IDENTITY,
            native_protocols=("native.v1", "native.v1"),
        )

    with pytest.raises(ProviderAdapterContractError, match="UNSUPPORTED_TRUST_BOUNDARY"):
        ProviderAdapterManifest(
            adapter_id="example.v1",
            provider_id="example",
            layer=Layer.IDENTITY,
            native_protocols=("native.v1",),
            trust_boundary="SELF_ASSERTED",
        )


def test_output_validator_binds_manifest_provider_layer_operation_and_time() -> None:
    item = manifest()
    good = validate_adapter_output(item, envelope(), expected_operation_id="op-r9")
    assert good.valid is True
    assert good.reason_codes == ()

    wrong = EvidenceEnvelope(
        layer=Layer.AUTHORIZATION,
        provider="attacker",
        operation_id="other-op",
        decision="ok",
        verdict=Verdict.PASS,
        subject_digest="not-a-digest",
        evidence_digest="not-a-digest",
        issued_at="2030-01-02T00:00:00+00:00",
        expires_at="2030-01-01T00:00:00+00:00",
    )
    result = validate_adapter_output(item, wrong, expected_operation_id="op-r9")
    assert result.valid is False
    assert "ADAPTER_OUTPUT_LAYER_MISMATCH" in result.reason_codes
    assert "ADAPTER_OUTPUT_PROVIDER_MISMATCH" in result.reason_codes
    assert "ADAPTER_OUTPUT_OPERATION_ID_MISMATCH" in result.reason_codes
    assert "INVALID_ADAPTER_OUTPUT_SUBJECT_DIGEST" in result.reason_codes
    assert "INVALID_ADAPTER_OUTPUT_EVIDENCE_DIGEST" in result.reason_codes
    assert "INVALID_ADAPTER_OUTPUT_TIME_WINDOW" in result.reason_codes


def test_generic_conformance_profile_enforces_all_mandatory_scenarios() -> None:
    source = {"authority": {"trusted": True}}
    original = deepcopy(source)

    def valid() -> EvidenceEnvelope:
        return envelope()

    def fail() -> EvidenceEnvelope:
        raise FakeAdapterError("fail closed")

    def mutation_isolated() -> EvidenceEnvelope:
        verifier_input = deepcopy(source)
        verifier_input["authority"]["trusted"] = False
        return envelope()

    cases = (
        ProviderConformanceCase(ConformanceScenario.VALID, valid, "op-r9"),
        ProviderConformanceCase(ConformanceScenario.OPERATION_MISMATCH, fail, "op-r9"),
        ProviderConformanceCase(ConformanceScenario.UNTRUSTED_AUTHORITY, fail, "op-r9"),
        ProviderConformanceCase(ConformanceScenario.AUTHORITY_ERROR, fail, "op-r9"),
        ProviderConformanceCase(
            ConformanceScenario.MUTATION_ISOLATION,
            mutation_isolated,
            "op-r9",
            postcondition=lambda _envelope: source == original,
        ),
        ProviderConformanceCase(ConformanceScenario.DETERMINISM, valid, "op-r9"),
    )

    report = run_provider_conformance(
        manifest(),
        adapter_error=FakeAdapterError,
        cases=cases,
    )

    assert report.contract == "operationproof.provider-conformance.v1"
    assert report.passed is True
    assert report.reason_codes == ()
    assert [item.scenario for item in report.cases] == [item.value for item in ConformanceScenario]


def test_conformance_cannot_silently_omit_a_required_failure_case() -> None:
    cases = (
        ProviderConformanceCase(ConformanceScenario.VALID, envelope, "op-r9"),
    )
    with pytest.raises(ProviderConformanceError, match="MISSING_CONFORMANCE_SCENARIOS"):
        run_provider_conformance(
            manifest(),
            adapter_error=FakeAdapterError,
            cases=cases,
        )


def test_failure_scenario_returning_evidence_is_a_conformance_failure() -> None:
    cases = tuple(
        ProviderConformanceCase(
            scenario,
            envelope if scenario is not ConformanceScenario.AUTHORITY_ERROR else envelope,
            "op-r9",
        )
        for scenario in ConformanceScenario
    )
    report = run_provider_conformance(
        manifest(),
        adapter_error=FakeAdapterError,
        cases=cases,
    )
    assert report.passed is False
    assert any("FAIL_CLOSED_CASE_RETURNED_EVIDENCE" in code for code in report.reason_codes)
