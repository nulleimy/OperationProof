from __future__ import annotations

from typing import Any, cast

from operationproof.canonical import sha256_digest
from operationproof.domain import EvidenceEnvelope, Layer, Verdict
from operationproof.provider import ProviderAdapterManifest, validate_adapter_output


def manifest() -> ProviderAdapterManifest:
    return ProviderAdapterManifest(
        adapter_id="example.identity.v1",
        provider_id="example-idp",
        layer=Layer.IDENTITY,
        native_protocols=("example.identity.v1",),
    )


def test_manifest_adapter_id_is_bound_to_normalized_metadata() -> None:
    item = EvidenceEnvelope(
        layer=Layer.IDENTITY,
        provider="example-idp",
        operation_id="op-r9",
        decision="VERIFIED",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": "r9"}),
        evidence_digest=sha256_digest({"evidence": "r9"}),
        issued_at="2030-01-01T00:00:00+00:00",
        metadata={"adapter": "different-adapter.v1"},
    )

    result = validate_adapter_output(manifest(), item, expected_operation_id="op-r9")

    assert result.valid is False
    assert "ADAPTER_OUTPUT_ADAPTER_ID_MISMATCH" in result.reason_codes


def test_malformed_runtime_dataclass_values_return_reasons_instead_of_raising() -> None:
    item = EvidenceEnvelope(
        layer=cast(Any, "identity"),
        provider="example-idp",
        operation_id="op-r9",
        decision="VERIFIED",
        verdict=cast(Any, "PASS"),
        subject_digest=sha256_digest({"subject": "r9"}),
        evidence_digest=sha256_digest({"evidence": "r9"}),
        issued_at="2030-01-01T00:00:00+00:00",
        metadata={"adapter": "example.identity.v1"},
    )

    result = validate_adapter_output(manifest(), item, expected_operation_id="op-r9")

    assert result.valid is False
    assert "INVALID_ADAPTER_OUTPUT_LAYER" in result.reason_codes
    assert "INVALID_ADAPTER_OUTPUT_VERDICT" in result.reason_codes
    assert "ADAPTER_OUTPUT_NOT_CANONICAL_JSON" in result.reason_codes
