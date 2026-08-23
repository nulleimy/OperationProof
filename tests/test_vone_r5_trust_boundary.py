from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest

from operationproof.adapters.vone import VOneAuthorizationError, VOneExecutionGrantAdapter
from operationproof.canonical import canonical_json_bytes

_OPERATION_ID = "execution-r5-boundary"
_NOW = datetime(2030, 1, 1, 0, 0, 30, tzinfo=UTC)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _rehash(grant: dict[str, Any]) -> None:
    payload = {key: value for key, value in grant.items() if key != "grant_digest"}
    grant["grant_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _grant() -> dict[str, Any]:
    grant: dict[str, Any] = {
        "schema_version": 2,
        "grant_type": "execution-grant/v2",
        "grant_id": "grant_boundary",
        "jti": "jti_boundary",
        "execution_id": _OPERATION_ID,
        "request_id": "request_boundary",
        "authorization_snapshot_digest": _digest("snapshot"),
        "snapshot_authority_witness_set_digest": _digest("witness-set"),
        "snapshot_authority_event_hash": _digest("event-hash"),
        "parent_scope_digest": _digest("parent-scope"),
        "authority_constraint_digest": _digest("authority-constraint"),
        "monotonic_authority_decision_digest": _digest("monotonic-decision"),
        "actor_id": "actor_boundary",
        "workspace_id": "workspace_boundary",
        "environment": "production",
        "capability": "deploy.release/v1",
        "capability_definition_identity": _digest("capability-definition"),
        "target_kind": "deployment",
        "target_digest": _digest("target"),
        "payload_digest": _digest("payload"),
        "policy_version": "policy/v1",
        "policy_identity": _digest("policy"),
        "approval_set_digest": _digest("approval-set"),
        "required_permission": "execution.run",
        "precondition_requirement_digest": _digest("precondition-requirement"),
        "precondition_expectation_digest": _digest("precondition-expectation"),
        "precondition_observation_digest": _digest("precondition-observation"),
        "precondition_witness_digest": _digest("precondition-witness"),
        "precondition_enforcement_class": "READ_THEN_COMPARE",
        "precondition_checked_at": "2030-01-01T00:00:00.000+00:00",
        "execution_binding_digest": _digest("execution-binding"),
        "execution_capsule_digest": _digest("execution-capsule"),
        "runner_class": "governed-runner/v1",
        "execution_binding_authority_revision": "binding-revision-1",
        "issued_at": "2030-01-01T00:00:10.000+00:00",
        "expires_at": "2030-01-01T00:01:10.000+00:00",
        "revocation_epoch": 7,
        "use_semantics": "ONE_TIME",
        "issuer_identity": "vone-authoritative-grant-issuer",
        "issuer_revision": "issuer-revision-1",
        "grant_digest": "",
    }
    _rehash(grant)
    return grant


def _adapt(grant: dict[str, Any], verifier: Any) -> Any:
    return VOneExecutionGrantAdapter.adapt(
        operation_id=_OPERATION_ID,
        grant=grant,
        grant_verifier=verifier,
        now=_NOW,
    )


def test_future_issued_grant_fails_closed() -> None:
    grant = _grant()
    grant["precondition_checked_at"] = "2030-01-01T00:00:30.000+00:00"
    grant["issued_at"] = "2030-01-01T00:00:40.000+00:00"
    grant["expires_at"] = "2030-01-01T00:01:40.000+00:00"
    _rehash(grant)

    with pytest.raises(VOneAuthorizationError, match="VONE_GRANT_NOT_YET_VALID"):
        _adapt(grant, lambda _grant: True)


def test_verifier_candidate_mutation_cannot_change_normalized_evidence() -> None:
    baseline_grant = _grant()
    baseline = _adapt(baseline_grant, lambda _grant: True)

    grant = _grant()

    def mutate_candidate(candidate: dict[str, Any]) -> bool:
        candidate["actor_id"] = "attacker"
        candidate["payload_digest"] = _digest("attacker-payload")
        candidate["issuer_revision"] = "attacker-revision"
        return True

    hardened = _adapt(grant, mutate_candidate)

    assert hardened.to_dict() == baseline.to_dict()
    assert grant["actor_id"] == "actor_boundary"
    assert grant["issuer_revision"] == "issuer-revision-1"


def test_verifier_closure_mutation_of_caller_grant_cannot_change_evidence() -> None:
    baseline = _adapt(_grant(), lambda _grant: True)
    grant = _grant()

    def mutate_caller(_candidate: object) -> bool:
        grant["actor_id"] = "attacker"
        grant["grant_digest"] = _digest("attacker-grant")
        return True

    hardened = _adapt(grant, mutate_caller)

    assert hardened.to_dict() == baseline.to_dict()
    assert grant["actor_id"] == "attacker"
    assert hardened.metadata["grant_digest"] == baseline.metadata["grant_digest"]


def test_operation_identity_is_exact_vone_execution_identity() -> None:
    grant = _grant()
    grant["execution_id"] = "different-vone-execution"
    _rehash(grant)

    with pytest.raises(VOneAuthorizationError, match="VONE_EXECUTION_ID_MISMATCH"):
        _adapt(grant, lambda _grant: True)
