# Execution Receipts and CASER Provider

## Purpose

R4 defines a vendor-neutral `operationproof.execution-receipt.v1` and a CASER adapter that
normalizes the existing CASER `execution-receipt/v1` plus `verification-result/v1` into canonical
OperationProof execution evidence.

OperationProof does not replace the CASER/SandCloud runner or its independent verifier.

## Native CASER baseline

The existing CASER runner emits `execution-receipt/v1`. Its independent verifier emits
`verification-result/v1`, identifies itself as `caser-independent-verifier/v0.1`, and can verify
receipt schema/content identity through an independent code path.

The observed V2 baseline explicitly states:

- receipt integrity verified: true;
- execution outcome independently verified: false;
- provider post-state verified: false.

Therefore R4 never promotes the existing V2 baseline to execution PASS merely because receipt
integrity succeeds.

## Canonical ExecutionReceipt

The normalized contract binds:

- exact provider;
- exact `operation_id`;
- exact PRE proof digest;
- execution instance identity;
- native receipt and verification content identities;
- verified effect class;
- execution outcome and whether that outcome was independently verified;
- receipt-integrity and provider-post-state claims;
- trusted validity window;
- deterministic receipt digest.

The canonical receipt is content-addressed, but its digest is not a provider-authenticity proof.
Provider authenticity remains an R3 `ProviderTrustRegistry` concern.

## CASER trusted execution binding

A native CASER receipt does not by itself contain an OperationProof PRE proof digest. Native
`contentIdentity` fields are also provider-owned references: OperationProof must not assume that a
self-claimed native identity authenticates the exact JSON document supplied to the adapter.

R4 therefore requires `operationproof.caser-execution-binding.v1`, covering:

- `operation_id`;
- exact `pre_proof_digest`;
- native receipt content identity;
- native verification content identity;
- OperationProof canonical SHA-256 digest of the complete native receipt document;
- OperationProof canonical SHA-256 digest of the complete native verification document;
- execution instance id;
- issued and expiry timestamps;
- deterministic binding digest.

The two OperationProof-local document digests prevent a trusted binding from being replayed after
claims, checks, scope, outcome, or other native document content changes while a native
`contentIdentity` string is retained. They establish exact-content binding, not provider identity.

An external `binding_verifier` must authenticate the binding through a trust mechanism outside the
OperationProof proof document. The verifier must treat the bound payload—including both exact
document digests—as authoritative input. Missing, false, expired, tampered, or throwing
verification fails closed.

## Independent outcome and post-state requirements

Stronger execution claims require stronger native verification evidence:

- `executionOutcomeIndependentlyVerified=true` requires `runnerIndependent=true`, an
  outcome-capable verification scope, and a PASS `execution-outcome` check whose observation equals
  the claimed outcome;
- a PASS `read-only-effect` check must observe exactly `READ_ONLY`; contradictory effect evidence is
  rejected;
- `providerPostStateVerified=true` requires `runnerIndependent=true`, exact scope
  `EXECUTION_OUTCOME_AND_PROVIDER_POST_STATE`, verification class
  `INDEPENDENT_PROVIDER_OBSERVATION`, a PASS `provider-post-state` check, and observation
  `VERIFIED`;
- every verification check name is scanned before claims are consumed; duplicate check names are
  rejected even if that check would otherwise be unused.

The post-state scope/class above describes future stronger provider evidence used by conformance
fixtures. It does not claim that the currently evidenced CASER V2 deployment provides V3/provider
post-state verification.

## Verdict mapping

| Native evidence | OperationProof execution verdict |
| --- | --- |
| verification status `FAIL` | `FAIL` |
| receipt integrity PASS but execution outcome unverified | `UNKNOWN` |
| independently verified outcome `FAILED` | `FAIL` |
| independently verified `SUCCEEDED` + verified `READ_ONLY` | `PASS` |
| independently verified `SUCCEEDED` + `MUTATING` + provider post-state verified | `PASS` |
| mutating execution without provider post-state verification | `UNKNOWN` |
| unknown effect class | `UNKNOWN` |

`UNKNOWN` keeps `FinalOperationProof` rejected. It is audit-valid evidence of insufficient assurance,
not a silent success.

## Trust boundary

Four properties remain deliberately separate:

1. `verify_proof()` verifies OperationProof structure, digests, deterministic semantics, and PRE/FINAL binding.
2. the CASER adapter validates native receipt/verification consistency and maps claims fail-closed.
3. `binding_verifier` authenticates the exact PRE/receipt/verification binding out of band.
4. `verify_proof_trust()` verifies provider authenticity using deployment-owned trust configuration and recursively requires trusted PRE evidence for FINAL proofs.

A production consumer should require all relevant gates. Adapter normalization alone is not runtime
authority. Native content identities, metadata strings, local canonical hashes, or self-asserted
provider names never establish trust roots.
