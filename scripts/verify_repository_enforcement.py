from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from operationproof.governance import (
    GovernanceVerificationError,
    verify_branch_summary,
    verify_protection_document,
)


def _gh_json(endpoint: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["gh", "api", endpoint],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit("GOVERNANCE_VERIFY_ERROR: gh CLI is not installed") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "GitHub API request failed"
        raise SystemExit(f"GOVERNANCE_VERIFY_ERROR: {detail}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit("GOVERNANCE_VERIFY_ERROR: GitHub response is not JSON") from exc
    if not isinstance(value, dict):
        raise SystemExit("GOVERNANCE_VERIFY_ERROR: GitHub response is not an object")
    return value


def _repository_owner_type(repository: dict[str, Any]) -> str:
    owner = repository.get("owner")
    if not isinstance(owner, dict):
        raise GovernanceVerificationError("repository owner is missing")
    owner_type = owner.get("type")
    if owner_type not in {"User", "Organization"}:
        raise GovernanceVerificationError("repository owner type is invalid")
    return owner_type


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify OperationProof GitHub governance")
    parser.add_argument("--repo", required=True, help="owner/repository")
    parser.add_argument(
        "--policy",
        default=str(ROOT / ".github/governance/main-protection.v1.json"),
    )
    args = parser.parse_args()

    policy_path = Path(args.policy)
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"GOVERNANCE_VERIFY_ERROR: invalid policy file: {policy_path}") from exc
    if not isinstance(policy, dict):
        raise SystemExit("GOVERNANCE_VERIFY_ERROR: policy is not an object")

    branch = policy.get("branch")
    if not isinstance(branch, str) or not branch:
        raise SystemExit("GOVERNANCE_VERIFY_ERROR: policy branch is invalid")

    try:
        repository_document = _gh_json(f"repos/{args.repo}")
        repository_owner_type = _repository_owner_type(repository_document)
        branch_document = _gh_json(f"repos/{args.repo}/branches/{branch}")
        protection_document = _gh_json(f"repos/{args.repo}/branches/{branch}/protection")
        branch_reasons = verify_branch_summary(branch_document, policy)
        protection_reasons = verify_protection_document(
            protection_document,
            policy,
            repository_owner_type=repository_owner_type,
        )
    except GovernanceVerificationError as exc:
        raise SystemExit(f"GOVERNANCE_VERIFY_ERROR: {exc}") from exc

    reasons = tuple(sorted(set(branch_reasons + protection_reasons)))
    report = {
        "schema": "operationproof.repository-governance-verification.v1",
        "repo": args.repo,
        "repository_owner_type": repository_owner_type,
        "branch": branch,
        "verified": not reasons,
        "reason_codes": list(reasons),
        "required_checks": policy["required_status_checks"]["contexts"],
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if not reasons else 1


if __name__ == "__main__":
    raise SystemExit(main())
