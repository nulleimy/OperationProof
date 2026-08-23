from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


class GovernanceVerificationError(ValueError):
    """Raised when a repository-governance document is malformed."""


def _require_bool(value: object, *, field: str) -> bool:
    if type(value) is not bool:
        raise GovernanceVerificationError(f"{field} must be boolean")
    return value


def _enabled(value: object) -> bool | None:
    if isinstance(value, Mapping):
        enabled = value.get("enabled")
        return enabled if type(enabled) is bool else None
    return value if type(value) is bool else None


def _required_contexts(protection: Mapping[str, Any]) -> set[str]:
    status = protection.get("required_status_checks")
    if not isinstance(status, Mapping):
        return set()

    contexts: set[str] = set()
    raw_contexts = status.get("contexts")
    if isinstance(raw_contexts, Sequence) and not isinstance(raw_contexts, (str, bytes)):
        contexts.update(item for item in raw_contexts if isinstance(item, str))

    raw_checks = status.get("checks")
    if isinstance(raw_checks, Sequence) and not isinstance(raw_checks, (str, bytes)):
        for item in raw_checks:
            if isinstance(item, Mapping) and isinstance(item.get("context"), str):
                contexts.add(item["context"])
    return contexts


def _has_pull_request_bypass(value: object) -> bool:
    if value is None:
        return False
    if not isinstance(value, Mapping):
        return True

    for key in ("users", "teams", "apps"):
        actors = value.get(key)
        if actors is None:
            continue
        if not isinstance(actors, Sequence) or isinstance(actors, (str, bytes)):
            return True
        if actors:
            return True
    return False


def verify_protection_document(
    protection: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> tuple[str, ...]:
    """Verify GitHub's full branch-protection response against the canonical policy."""

    reasons: list[str] = []

    required = policy.get("required_status_checks")
    if not isinstance(required, Mapping):
        raise GovernanceVerificationError("policy.required_status_checks is invalid")
    expected_contexts = required.get("contexts")
    if not isinstance(expected_contexts, list) or not all(
        isinstance(item, str) and item for item in expected_contexts
    ):
        raise GovernanceVerificationError("policy required status contexts are invalid")
    if len(expected_contexts) != len(set(expected_contexts)):
        raise GovernanceVerificationError("policy required status contexts are duplicated")

    status = protection.get("required_status_checks")
    if not isinstance(status, Mapping):
        reasons.append("REQUIRED_STATUS_CHECKS_MISSING")
    else:
        if status.get("strict") is not True:
            reasons.append("REQUIRED_STATUS_CHECKS_NOT_STRICT")
        expected_set = set(expected_contexts)
        live_set = _required_contexts(protection)
        missing = sorted(expected_set - live_set)
        unexpected = sorted(live_set - expected_set)
        reasons.extend(f"REQUIRED_STATUS_CHECK_MISSING:{name}" for name in missing)
        reasons.extend(f"UNEXPECTED_REQUIRED_STATUS_CHECK:{name}" for name in unexpected)

    if _enabled(protection.get("enforce_admins")) is not True:
        reasons.append("ADMIN_ENFORCEMENT_DISABLED")

    pull_request = protection.get("required_pull_request_reviews")
    expected_pr = policy.get("pull_request")
    if not isinstance(expected_pr, Mapping):
        raise GovernanceVerificationError("policy.pull_request is invalid")
    if expected_pr.get("required") is True:
        if not isinstance(pull_request, Mapping):
            reasons.append("PULL_REQUEST_GATE_MISSING")
        else:
            if pull_request.get("dismiss_stale_reviews") is not _require_bool(
                expected_pr.get("dismiss_stale_reviews"), field="dismiss_stale_reviews"
            ):
                reasons.append("DISMISS_STALE_REVIEWS_MISMATCH")
            if pull_request.get("require_code_owner_reviews") is not _require_bool(
                expected_pr.get("require_code_owner_reviews"),
                field="require_code_owner_reviews",
            ):
                reasons.append("CODE_OWNER_REVIEW_POLICY_MISMATCH")
            if pull_request.get("required_approving_review_count") != expected_pr.get(
                "required_approving_review_count"
            ):
                reasons.append("APPROVING_REVIEW_COUNT_MISMATCH")
            if pull_request.get("require_last_push_approval") is not _require_bool(
                expected_pr.get("require_last_push_approval"),
                field="require_last_push_approval",
            ):
                reasons.append("LAST_PUSH_APPROVAL_POLICY_MISMATCH")
            allow_bypass = _require_bool(expected_pr.get("allow_bypass"), field="allow_bypass")
            if not allow_bypass and _has_pull_request_bypass(
                pull_request.get("bypass_pull_request_allowances")
            ):
                reasons.append("PULL_REQUEST_BYPASS_ALLOWANCE_PRESENT")

    booleans = (
        ("required_conversation_resolution", "CONVERSATION_RESOLUTION_DISABLED"),
        ("allow_force_pushes", "FORCE_PUSH_POLICY_MISMATCH"),
        ("allow_deletions", "DELETION_POLICY_MISMATCH"),
        ("block_creations", "CREATION_POLICY_MISMATCH"),
        ("lock_branch", "BRANCH_LOCK_POLICY_MISMATCH"),
    )
    for field, code in booleans:
        expected = _require_bool(policy.get(field), field=field)
        actual = _enabled(protection.get(field))
        if actual is not expected:
            reasons.append(code)

    return tuple(sorted(set(reasons)))


def verify_branch_summary(
    branch: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> tuple[str, ...]:
    """Verify the public/read-only branch summary exposed by GitHub."""

    reasons: list[str] = []
    expected_branch = policy.get("branch")
    if not isinstance(expected_branch, str) or not expected_branch:
        raise GovernanceVerificationError("policy.branch is invalid")
    if branch.get("name") != expected_branch:
        reasons.append("BRANCH_NAME_MISMATCH")
    if branch.get("protected") is not True:
        reasons.append("BRANCH_NOT_PROTECTED")

    protection = branch.get("protection")
    if not isinstance(protection, Mapping) or protection.get("enabled") is not True:
        reasons.append("BRANCH_PROTECTION_NOT_ENABLED")

    return tuple(sorted(set(reasons)))
