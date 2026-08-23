from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from operationproof.adapters import (
    CASER_ADAPTER_MANIFEST,
    HOWEDO_ADAPTER_MANIFEST,
    VONE_ADAPTER_MANIFEST,
    CaserExecutionAdapter,
    CaserExecutionError,
    HowedoWitnessAdapter,
    HowedoWitnessError,
    VOneAuthorizationError,
    VOneExecutionGrantAdapter,
)
from operationproof.builder import build_pre_proof
from operationproof.canonical import canonical_json_bytes, sha256_digest
from operationproof.conformance import (
    ConformanceScenario,
    ProviderConformanceCase,
    run_provider_conformance,
)
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict


def _howedo_witness() -> dict[str, object]:
    snapshot_id = sha256_digest({"snapshot": "r9"})
    reasons = ("STATE_UNCHANGED",)
    return {
        "snapshot_id": snapshot_id,
        "action": "CONTINUE",
        "reason_codes": list(reasons),
        "witness_digest": sha256_digest(
            {
                "action": "CONTINUE",
                "reason_codes": reasons,
                "snapshot_id": snapshot_id,
            }
        ),
    }


def _howedo_binding(witness: dict[str, object], operation_id: str = "op-r9-howedo") -> dict[str, object]:
    payload = {
        "schema": "operationproof.howedo-binding.v1",
        "operation_id": operation_id,
        "snapshot_id": witness["snapshot_id"],
        "witness_digest": witness["witness_digest"],
        "issued_at": "2030-01-01T00:00:00+00:00",
        "expires_at": "2035-01-01T00:00:00+00:00",
    }
    return {**payload, "binding_digest": sha256_digest(payload), "attestation": "trusted"}


def _howedo_valid() -> EvidenceEnvelope:
    witness = _howedo_witness()
    binding = _howedo_binding(witness)
    return HowedoWitnessAdapter.adapt(
        operation_id="op-r9-howedo",
        witness=witness,
        binding=binding,
        binding_verifier=lambda item: item.get("attestation") == "trusted",
    )


def _howedo_suite() -> tuple[ProviderConformanceCase, ...]:
    mutation_state: dict[str, object] = {}

    def mismatch() -> EvidenceEnvelope:
        witness = _howedo_witness()
        return HowedoWitnessAdapter.adapt(
            operation_id="op-r9-howedo-other",
            witness=witness,
            binding=_howedo_binding(witness),
            binding_verifier=lambda _item: True,
        )

    def untrusted() -> EvidenceEnvelope:
        witness = _howedo_witness()
        return HowedoWitnessAdapter.adapt(
            operation_id="op-r9-howedo",
            witness=witness,
            binding=_howedo_binding(witness),
            binding_verifier=lambda _item: False,
        )

    def authority_error() -> EvidenceEnvelope:
        witness = _howedo_witness()

        def explode(_item: object) -> bool:
            raise RuntimeError("authority unavailable")

        return HowedoWitnessAdapter.adapt(
            operation_id="op-r9-howedo",
            witness=witness,
            binding=_howedo_binding(witness),
            binding_verifier=explode,
        )

    def mutation() -> EvidenceEnvelope:
        witness = _howedo_witness()
        binding = _howedo_binding(witness)
        mutation_state["witness"] = witness
        mutation_state["binding"] = binding
        mutation_state["witness_before"] = deepcopy(witness)
        mutation_state["binding_before"] = deepcopy(binding)

        def mutate(item: object) -> bool:
            assert isinstance(item, dict)
            item["operation_id"] = "attacker"
            item["binding_digest"] = "attacker"
            return True

        return HowedoWitnessAdapter.adapt(
            operation_id="op-r9-howedo",
            witness=witness,
            binding=binding,
            binding_verifier=mutate,
        )

    def mutation_postcondition(_envelope: EvidenceEnvelope) -> bool:
        return bool(
            mutation_state["witness"] == mutation_state["witness_before"]
            and mutation_state["binding"] == mutation_state["binding_before"]
        )

    return (
        ProviderConformanceCase(ConformanceScenario.VALID, _howedo_valid, "op-r9-howedo"),
        ProviderConformanceCase(ConformanceScenario.OPERATION_MISMATCH, mismatch, "op-r9-howedo"),
        ProviderConformanceCase(ConformanceScenario.UNTRUSTED_AUTHORITY, untrusted, "op-r9-howedo"),
        ProviderConformanceCase(ConformanceScenario.AUTHORITY_ERROR, authority_error, "op-r9-howedo"),
        ProviderConformanceCase(
            ConformanceScenario.MUTATION_ISOLATION,
            mutation,
            "op-r9-howedo",
            postcondition=mutation_postcondition,
        ),
        ProviderConformanceCase(ConformanceScenario.DETERMINISM, _howedo_valid, "op-r9-howedo"),
    )


def _native_digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _recompute_vone_digest(grant: dict[str, Any]) -> None:
    payload = {key: value for key, value in grant.items() if key != "grant_digest"}
    grant["grant_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _vone_grant() -> dict[str, Any]:
    grant: dict[str, Any] = {
        "schema_version": 2,
        "grant_type": "execution-grant/v2",
        "grant_id": "grant_r9",
        "jti": "jti_r9",
        "execution_id": "op-r9-vone",
        "request_id": "request_r9",
        "authorization_snapshot_digest": _native_digest("snapshot-r9"),
        "snapshot_authority_witness_set_digest": _native_digest("witness-set-r9"),
        "snapshot_authority_event_hash": _native_digest("event-r9"),
        "parent_scope_digest": _native_digest("scope-r9"),
        "authority_constraint_digest": _native_digest("constraint-r9"),
        "monotonic_authority_decision_digest": _native_digest("decision-r9"),
        "actor_id": "actor_r9",
        "workspace_id": "workspace_r9",
        "environment": "production",
        "capability": "deploy.release/v1",
        "capability_definition_identity": _native_digest("capability-r9"),
        "target_kind": "deployment",
        "target_digest": _native_digest("target-r9"),
        "payload_digest": _native_digest("payload-r9"),
        "policy_version": "policy/v1",
        "policy_identity": _native_digest("policy-r9"),
        "approval_set_digest": _native_digest("approval-r9"),
        "required_permission": "execution.run",
        "precondition_requirement_digest": _native_digest("req-r9"),
        "precondition_expectation_digest": _native_digest("expect-r9"),
        "precondition_observation_digest": _native_digest("observe-r9"),
        "precondition_witness_digest": _native_digest("precondition-r9"),
        "precondition_enforcement_class": "READ_THEN_COMPARE",
        "precondition_checked_at": "2030-01-01T00:00:00.000+00:00",
        "execution_binding_digest": _native_digest("execution-binding-r9"),
        "execution_capsule_digest": _native_digest("capsule-r9"),
        "runner_class": "governed-runner/v1",
        "execution_binding_authority_revision": "binding-revision-r9",
        "issued_at": "2030-01-01T00:00:10.000+00:00",
        "expires_at": "2030-01-01T00:01:10.000+00:00",
        "revocation_epoch": 9,
        "use_semantics": "ONE_TIME",
        "issuer_identity": "vone-authoritative-grant-issuer",
        "issuer_revision": "issuer-revision-r9",
        "grant_digest": "",
    }
    _recompute_vone_digest(grant)
    return grant


_VONE_NOW = datetime(2030, 1, 1, 0, 0, 30, tzinfo=UTC)


def _vone_valid() -> EvidenceEnvelope:
    return VOneExecutionGrantAdapter.adapt(
        operation_id="op-r9-vone",
        grant=_vone_grant(),
        grant_verifier=lambda _grant: True,
        now=_VONE_NOW,
    )


def _vone_suite() -> tuple[ProviderConformanceCase, ...]:
    mutation_state: dict[str, object] = {}

    def mismatch() -> EvidenceEnvelope:
        return VOneExecutionGrantAdapter.adapt(
            operation_id="op-r9-vone-other",
            grant=_vone_grant(),
            grant_verifier=lambda _grant: True,
            now=_VONE_NOW,
        )

    def untrusted() -> EvidenceEnvelope:
        return VOneExecutionGrantAdapter.adapt(
            operation_id="op-r9-vone",
            grant=_vone_grant(),
            grant_verifier=lambda _grant: False,
            now=_VONE_NOW,
        )

    def authority_error() -> EvidenceEnvelope:
        def explode(_grant: object) -> bool:
            raise RuntimeError("authority unavailable")

        return VOneExecutionGrantAdapter.adapt(
            operation_id="op-r9-vone",
            grant=_vone_grant(),
            grant_verifier=explode,
            now=_VONE_NOW,
        )

    def mutation() -> EvidenceEnvelope:
        grant = _vone_grant()
        mutation_state["grant"] = grant
        mutation_state["before"] = deepcopy(grant)

        def mutate(verifier_grant: object) -> bool:
            assert isinstance(verifier_grant, dict)
            verifier_grant["issuer_revision"] = "attacker"
            verifier_grant["grant_digest"] = "attacker"
            return True

        return VOneExecutionGrantAdapter.adapt(
            operation_id="op-r9-vone",
            grant=grant,
            grant_verifier=mutate,
            now=_VONE_NOW,
        )

    return (
        ProviderConformanceCase(ConformanceScenario.VALID, _vone_valid, "op-r9-vone"),
        ProviderConformanceCase(ConformanceScenario.OPERATION_MISMATCH, mismatch, "op-r9-vone"),
        ProviderConformanceCase(ConformanceScenario.UNTRUSTED_AUTHORITY, untrusted, "op-r9-vone"),
        ProviderConformanceCase(ConformanceScenario.AUTHORITY_ERROR, authority_error, "op-r9-vone"),
        ProviderConformanceCase(
            ConformanceScenario.MUTATION_ISOLATION,
            mutation,
            "op-r9-vone",
            postcondition=lambda _envelope: mutation_state["grant"] == mutation_state["before"],
        ),
        ProviderConformanceCase(ConformanceScenario.DETERMINISM, _vone_valid, "op-r9-vone"),
    )


def _pre_evidence(layer: Layer) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"r9:{layer.value}",
        operation_id="op-r9-caser",
        decision="native-ok",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": layer.value}),
        evidence_digest=sha256_digest({"evidence": layer.value}),
        issued_at="2030-01-01T00:00:00+00:00",
    )


def _caser_pre() -> dict[str, object]:
    return build_pre_proof("op-r9-caser", [_pre_evidence(layer) for layer in PRE_LAYERS])


def _caser_receipt(operation_id: str = "op-r9-caser") -> dict[str, object]:
    return {
        "schemaVersion": "execution-receipt/v1",
        "operationId": operation_id,
        "instanceId": "receipt-r9",
        "contentIdentity": sha256_digest({"native": "receipt-r9"}),
    }


def _caser_verification(receipt: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": "verification-result/v1",
        "instanceId": "verification-r9",
        "verifierIdentity": "caser-independent-verifier/r9",
        "verifiedAt": "2030-01-01T00:01:00+00:00",
        "verificationStrength": "V2",
        "verificationClass": "INDEPENDENT_CODE_PATH",
        "verificationScope": "EXECUTION_EVIDENCE_INTEGRITY",
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
        ],
        "status": "PASS",
        "claims": {
            "receiptIntegrityVerified": True,
            "executionOutcomeIndependentlyVerified": False,
            "providerPostStateVerified": False,
        },
        "contentIdentity": sha256_digest({"native": "verification-r9"}),
    }


def _caser_binding(
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
        "issued_at": "2030-01-01T00:02:00+00:00",
        "expires_at": "2035-01-01T00:00:00+00:00",
    }
    return {**payload, "binding_digest": sha256_digest(payload), "attestation": "trusted"}


def _caser_valid() -> EvidenceEnvelope:
    pre = _caser_pre()
    receipt = _caser_receipt()
    verification = _caser_verification(receipt)
    return CaserExecutionAdapter.adapt(
        pre_proof=pre,
        receipt=receipt,
        verification=verification,
        binding=_caser_binding(pre, receipt, verification),
        binding_verifier=lambda item: item.get("attestation") == "trusted",
    )


def _caser_suite() -> tuple[ProviderConformanceCase, ...]:
    mutation_state: dict[str, object] = {}

    def mismatch() -> EvidenceEnvelope:
        pre = _caser_pre()
        receipt = _caser_receipt("other-op")
        verification = _caser_verification(receipt)
        return CaserExecutionAdapter.adapt(
            pre_proof=pre,
            receipt=receipt,
            verification=verification,
            binding=_caser_binding(pre, receipt, verification),
            binding_verifier=lambda _item: True,
        )

    def untrusted() -> EvidenceEnvelope:
        pre = _caser_pre()
        receipt = _caser_receipt()
        verification = _caser_verification(receipt)
        return CaserExecutionAdapter.adapt(
            pre_proof=pre,
            receipt=receipt,
            verification=verification,
            binding=_caser_binding(pre, receipt, verification),
            binding_verifier=lambda _item: False,
        )

    def authority_error() -> EvidenceEnvelope:
        pre = _caser_pre()
        receipt = _caser_receipt()
        verification = _caser_verification(receipt)

        def explode(_item: object) -> bool:
            raise RuntimeError("authority unavailable")

        return CaserExecutionAdapter.adapt(
            pre_proof=pre,
            receipt=receipt,
            verification=verification,
            binding=_caser_binding(pre, receipt, verification),
            binding_verifier=explode,
        )

    def mutation() -> EvidenceEnvelope:
        pre = _caser_pre()
        receipt = _caser_receipt()
        verification = _caser_verification(receipt)
        binding = _caser_binding(pre, receipt, verification)
        mutation_state["receipt"] = receipt
        mutation_state["verification"] = verification
        mutation_state["binding"] = binding
        mutation_state["before"] = deepcopy((receipt, verification, binding))

        def mutate(verifier_binding: object) -> bool:
            assert isinstance(verifier_binding, dict)
            verifier_binding["operation_id"] = "attacker"
            verifier_binding["binding_digest"] = "attacker"
            return True

        return CaserExecutionAdapter.adapt(
            pre_proof=pre,
            receipt=receipt,
            verification=verification,
            binding=binding,
            binding_verifier=mutate,
        )

    def mutation_postcondition(_envelope: EvidenceEnvelope) -> bool:
        before_receipt, before_verification, before_binding = mutation_state["before"]
        return bool(
            mutation_state["receipt"] == before_receipt
            and mutation_state["verification"] == before_verification
            and mutation_state["binding"] == before_binding
        )

    return (
        ProviderConformanceCase(ConformanceScenario.VALID, _caser_valid, "op-r9-caser"),
        ProviderConformanceCase(ConformanceScenario.OPERATION_MISMATCH, mismatch, "op-r9-caser"),
        ProviderConformanceCase(ConformanceScenario.UNTRUSTED_AUTHORITY, untrusted, "op-r9-caser"),
        ProviderConformanceCase(ConformanceScenario.AUTHORITY_ERROR, authority_error, "op-r9-caser"),
        ProviderConformanceCase(
            ConformanceScenario.MUTATION_ISOLATION,
            mutation,
            "op-r9-caser",
            postcondition=mutation_postcondition,
        ),
        ProviderConformanceCase(ConformanceScenario.DETERMINISM, _caser_valid, "op-r9-caser"),
    )


def test_howedo_passes_provider_conformance_profile() -> None:
    report = run_provider_conformance(
        HOWEDO_ADAPTER_MANIFEST,
        adapter_error=HowedoWitnessError,
        cases=_howedo_suite(),
    )
    assert report.passed is True, report.to_dict()


def test_vone_passes_provider_conformance_profile() -> None:
    report = run_provider_conformance(
        VONE_ADAPTER_MANIFEST,
        adapter_error=VOneAuthorizationError,
        cases=_vone_suite(),
    )
    assert report.passed is True, report.to_dict()


def test_caser_passes_provider_conformance_profile() -> None:
    report = run_provider_conformance(
        CASER_ADAPTER_MANIFEST,
        adapter_error=CaserExecutionError,
        cases=_caser_suite(),
    )
    assert report.passed is True, report.to_dict()
