#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-}"
POLICY="${2:-.github/governance/main-protection.v1.json}"

if [[ -z "$REPO" ]]; then
  echo "usage: $0 owner/repository [policy.json]" >&2
  exit 64
fi
if [[ ! -f "$POLICY" ]]; then
  echo "GOVERNANCE_APPLY_ERROR: policy file not found: $POLICY" >&2
  exit 66
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "GOVERNANCE_APPLY_ERROR: gh CLI is required" >&2
  exit 69
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "GOVERNANCE_APPLY_ERROR: python3 is required" >&2
  exit 69
fi

gh auth status >/dev/null
LOGIN="$(gh api user --jq .login)"
PERMISSION="$(gh api "repos/$REPO/collaborators/$LOGIN/permission" --jq .permission)"
if [[ "$PERMISSION" != "admin" ]]; then
  echo "GOVERNANCE_APPLY_ERROR: $LOGIN does not have admin permission on $REPO" >&2
  exit 77
fi

BRANCH="$(python3 - "$POLICY" <<'PY'
import json
import sys
from pathlib import Path
policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
branch = policy.get("branch")
if not isinstance(branch, str) or not branch:
    raise SystemExit("invalid governance branch")
print(branch)
PY
)"

python3 - "$POLICY" <<'PY' | gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "repos/$REPO/branches/$BRANCH/protection" \
  --input - >/dev/null
import json
import sys
from pathlib import Path

policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
checks = policy["required_status_checks"]
pull = policy["pull_request"]
payload = {
    "required_status_checks": {
        "strict": checks["strict"],
        "contexts": checks["contexts"],
    },
    "enforce_admins": policy["enforce_admins"],
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": pull["dismiss_stale_reviews"],
        "require_code_owner_reviews": pull["require_code_owner_reviews"],
        "required_approving_review_count": pull["required_approving_review_count"],
        "require_last_push_approval": pull["require_last_push_approval"],
    } if pull["required"] else None,
    "restrictions": None,
    "required_conversation_resolution": policy["required_conversation_resolution"],
    "allow_force_pushes": policy["allow_force_pushes"],
    "allow_deletions": policy["allow_deletions"],
    "block_creations": policy["block_creations"],
    "lock_branch": policy["lock_branch"],
}
print(json.dumps(payload, separators=(",", ":")))
PY

python3 scripts/verify_repository_enforcement.py --repo "$REPO" --policy "$POLICY"
