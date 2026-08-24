from __future__ import annotations

import pytest

from operationproof.canonical import sha256_digest
from operationproof.conformance import (
    ConformanceScenario,
    ProviderConformanceCase,
    ProviderConformanceError,
    run_provider_conformance,
)
from operationproof.domain import EvidenceEnvelope, Layer, Verdict
from operationproof.provider import ProviderAdapterManifest


class AdapterError(ValueError):
    pass


def envelope() -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=Layer.IDENTITY,
        provider="example-idp",
        operation_id="op-r9",
        decision="VERIFIED",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": "r9"}),
        evidence_digest=sha256_digest({"evidence": "r9"}),
        issued_at="2030-01-01T00:00:00+00:00",
        metadata={"adapter": "example.identity.v1"},
    )


def fail() -> EvidenceEnvelope:
    raise AdapterError("fail closed")


def test_mutation_isolation_scenario_requires_an_explicit_assertion() -> None:
    manifest = ProviderAdapterManifest(
        adapter_id="example.identity.v1",
        provider_id="example-idp",
        layer=Layer.IDENTITY,
        native_protocols=("example.identity.v1",),
    )
    cases = (
        ProviderConformanceCase(ConformanceScenario.VALID, envelope, "op-r9"),
        ProviderConformanceCase(ConformanceScenario.OPERATION_MISMATCH, fail, "op-r9"),
        ProviderConformanceCase(ConformanceScenario.UNTRUSTED_AUTHORITY, fail, "op-r9"),
        ProviderConformanceCase(ConformanceScenario.AUTHORITY_ERROR, fail, "op-r9"),
        ProviderConformanceCase(ConformanceScenario.MUTATION_ISOLATION, envelope, "op-r9"),
        ProviderConformanceCase(ConformanceScenario.DETERMINISM, envelope, "op-r9"),
    )

    with pytest.raises(
        ProviderConformanceError,
        match="MISSING_MUTATION_ISOLATION_POSTCONDITION",
    ):
        run_provider_conformance(
            manifest,
            adapter_error=AdapterError,
            cases=cases,
        )
