import pytest

from operationproof.adapters.caser import CaserExecutionAdapter, CaserExecutionError
from operationproof.builder import build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict


def _pre_evidence(layer: Layer) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"test:{layer.value}",
        operation_id="op-toctou",
        decision="native-ok",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": layer.value}),
        evidence_digest=sha256_digest({"evidence": layer.value}),
        issued_at="2026-08-23T00:00:00+00:00",
    )


def _verified_pre() -> dict[str, object]:
    return build_pre_proof("op-toctou", [_pre_evidence(layer) for layer in PRE_LAYERS])


def _receipt() -> dict[str, object]:
    return {
        "schemaVersion": "execution-receipt/v1",
        "operationId": "op-toctou",
        "instanceId": "receipt-toctou-1",
        "contentIdentity": sha256_digest({"native": "receipt-toctou-1"}),
    }


def _strong_verification(receipt: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": "verification-result/v1",
        "instanceId": "verification-toctou-1",
        "verifierIdentity": "caser-independent-verifier/v0.1",
        "verifiedAt": "2026-08-23T00:01:00+00:00",
        "verificationStrength": "V2",
        "verificationClass": "INDEPENDENT_CODE_PATH",
        "verificationScope": "EXECUTION_OUTCOME",
        "receipt": {
            "contentIdentity": receipt["contentIdentity"],
            "operationId": receipt["operationId"],
            "instanceId": receipt["instanceId"],
        },
        "runnerIndependent": True,
        "checks": [
            {
                "check": "receipt-schema",
                "status": "PASS",
                "observed": "execution-receipt/v1",
            },
            {
                "check": "content-identity",
                "status": "PASS",
                "observed": {
                    "claimed": receipt["contentIdentity"],
                    "calculated": receipt["contentIdentity"],
                },
            },
            {
                "check": "read-only-effect",
                "status": "PASS",
                "observed": "READ_ONLY",
            },
            {
                "check": "execution-outcome",
                "status": "PASS",
                "observed": "SUCCEEDED",
            },
        ],
        "status": "PASS",
        "claims": {
            "receiptIntegrityVerified": True,
            "executionOutcomeIndependentlyVerified": True,
            "providerPostStateVerified": False,
        },
        "executionOutcome": "SUCCEEDED",
        "contentIdentity": sha256_digest({"native": "verification-toctou-1"}),
    }


def _binding(
    pre: dict[str, object],
    receipt: dict[str, object],
    verification: dict[str, object],
) -> dict[str, object]:
    payload = {
        "schema": "operationproof.caser-execution-binding.v1",
        "operation_id": pre["operation_id"],
        "pre_proof_digest": pre["proof_digest"],
        "receipt_content_identity": receipt["contentIdentity"],
        "verification_content_identity": verification["contentIdentity"],
        "receipt_document_digest": sha256_digest(receipt),
        "verification_document_digest": sha256_digest(verification),
        "execution_instance_id": receipt["instanceId"],
        "issued_at": "2026-08-23T00:02:00+00:00",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }
    return {
        **payload,
        "binding_digest": sha256_digest(payload),
        "attestation": "trusted-test-binding",
    }


def test_verifier_callback_cannot_escalate_authenticated_v2_to_v3() -> None:
    pre = _verified_pre()
    receipt = _receipt()
    verification = _strong_verification(receipt)
    binding = _binding(pre, receipt, verification)

    def mutating_verifier(candidate: object) -> bool:
        verification["verificationStrength"] = "V3"
        return isinstance(candidate, dict) and candidate.get("attestation") == "trusted-test-binding"

    with pytest.raises(
        CaserExecutionError,
        match="CASER_V2_OUTSIDE_INTEGRITY_ONLY_SCOPE",
    ):
        CaserExecutionAdapter.adapt(
            pre_proof=pre,
            receipt=receipt,
            verification=verification,
            binding=binding,
            binding_verifier=mutating_verifier,
        )

    assert verification["verificationStrength"] == "V3"
