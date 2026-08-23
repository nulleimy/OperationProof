# Repository Governance Enforcement (G0)

OperationProof treats repository governance as part of the trust boundary. A green test suite is not sufficient if `main` can still be modified outside the reviewed PR path.

## Canonical policy

`.github/governance/main-protection.v1.json` is the repository-side source of truth for the expected GitHub `main` protection configuration.

Required controls:

- strict required checks: `test (3.12)` and `test (3.13)`
- PR gate enabled
- stale review dismissal enabled
- zero mandatory human approvals, so a single-maintainer repository is not deadlocked
- conversation resolution required
- administrator enforcement enabled
- force pushes disabled
- branch deletion disabled

Independent Codex review remains an OperationProof release gate, but it is not represented as a GitHub required approval because the current Codex integration publishes a review verdict/comment rather than a formal `APPROVE` review state.

## Apply

The GitHub account running the command must have repository admin permission and an authenticated `gh` CLI session.

```bash
bash scripts/apply_repository_enforcement.sh nulleimy/OperationProof
```

The script:

1. checks the authenticated GitHub identity and admin permission;
2. reads the canonical policy;
3. applies classic branch protection through the GitHub REST API;
4. immediately runs the fail-closed verifier;
5. exits non-zero unless the live protection document matches the policy.

The script intentionally does not use a repository-controlled GitHub Actions token to grant itself governance authority. Repository code must not be able to weaken or create its own protection boundary.

## Verify

```bash
python3 scripts/verify_repository_enforcement.py --repo nulleimy/OperationProof
```

A successful verification emits one compact JSON record with `verified:true` and exits `0`. Any missing, weakened, inaccessible, or malformed protection state exits non-zero.

## Trust boundary

The repository files in this slice define and verify the desired state; they do not, by themselves, prove that GitHub server-side protection is active.

Canonical G0 status is therefore:

```text
POLICY IMPLEMENTED + CI VERIFIED
    !=
LIVE GITHUB PROTECTION VERIFIED
```

G0 may be called fully enforced only after the live GitHub branch endpoint reports `protected:true` and the full protection verifier passes against the canonical policy.

## Required status check stability

The canonical CI workflow keeps the job id `test` and Python matrix values `3.12` / `3.13`, yielding the required contexts:

- `test (3.12)`
- `test (3.13)`

`tests/test_repository_governance.py` fails if the policy and CI contract drift apart.
