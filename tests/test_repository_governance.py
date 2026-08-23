from __future__ import annotations

import json
from pathlib import Path

from operationproof.governance import verify_branch_summary, verify_protection_document

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / ".github/governance/main-protection.v1.json"


def _policy() -> dict[str, object]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def _protection() -> dict[str, object]:
    return {
        "required_status_checks": {
            "strict": True,
            "contexts": ["test (3.12)", "test (3.13)"],
        },
        "enforce_admins": {"enabled": True},
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": False,
            "required_approving_review_count": 0,
            "require_last_push_approval": False,
            "bypass_pull_request_allowances": {
                "users": [],
                "teams": [],
                "apps": [],
            },
        },
        "required_conversation_resolution": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "block_creations": {"enabled": False},
        "lock_branch": {"enabled": False},
    }


def test_canonical_protection_document_passes() -> None:
    assert verify_protection_document(_protection(), _policy()) == ()


def test_missing_or_weakened_controls_fail_closed() -> None:
    protection = _protection()
    protection["enforce_admins"] = {"enabled": False}
    protection["allow_force_pushes"] = {"enabled": True}
    protection["required_status_checks"] = {
        "strict": False,
        "contexts": ["test (3.12)"],
    }

    reasons = verify_protection_document(protection, _policy())

    assert "ADMIN_ENFORCEMENT_DISABLED" in reasons
    assert "FORCE_PUSH_POLICY_MISMATCH" in reasons
    assert "REQUIRED_STATUS_CHECKS_NOT_STRICT" in reasons
    assert "REQUIRED_STATUS_CHECK_MISSING:test (3.13)" in reasons


def test_unexpected_required_check_fails_closed() -> None:
    protection = _protection()
    protection["required_status_checks"] = {
        "strict": True,
        "contexts": ["test (3.12)", "test (3.13)", "obsolete-check"],
    }

    reasons = verify_protection_document(protection, _policy())

    assert reasons == ("UNEXPECTED_REQUIRED_STATUS_CHECK:obsolete-check",)


def test_pull_request_bypass_actor_fails_closed() -> None:
    protection = _protection()
    reviews = protection["required_pull_request_reviews"]
    assert isinstance(reviews, dict)
    reviews["bypass_pull_request_allowances"] = {
        "users": [{"login": "bypass-user"}],
        "teams": [],
        "apps": [],
    }

    reasons = verify_protection_document(protection, _policy())

    assert reasons == ("PULL_REQUEST_BYPASS_ALLOWANCE_PRESENT",)


def test_check_objects_are_accepted_as_required_contexts() -> None:
    protection = _protection()
    protection["required_status_checks"] = {
        "strict": True,
        "contexts": [],
        "checks": [
            {"context": "test (3.12)", "app_id": 15368},
            {"context": "test (3.13)", "app_id": 15368},
        ],
    }

    assert verify_protection_document(protection, _policy()) == ()


def test_branch_summary_requires_protected_main() -> None:
    branch = {
        "name": "main",
        "protected": False,
        "protection": {
            "enabled": False,
            "required_status_checks": {
                "enforcement_level": "off",
                "contexts": [],
                "checks": [],
            },
        },
    }

    reasons = verify_branch_summary(branch, _policy())

    assert reasons == ("BRANCH_NOT_PROTECTED", "BRANCH_PROTECTION_NOT_ENABLED")


def test_governance_required_checks_match_explicit_ci_job_name() -> None:
    policy = _policy()
    checks = policy["required_status_checks"]
    assert isinstance(checks, dict)
    assert checks["contexts"] == ["test (3.12)", "test (3.13)"]

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "jobs:\n  test:" in workflow
    assert "    name: test (${{ matrix.python-version }})" in workflow
    assert 'python-version: ["3.12", "3.13"]' in workflow
