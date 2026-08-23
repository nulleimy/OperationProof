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

A native CASER receipt does not by itself contain an OperationProof PRE proof digest. R4 therefore
requires `operationproof.caser-execution-binding.v1`, covering:

- `operation_id`;
- `pre_proof_digest`;
- native receipt content identity;
- native verification content identity;
- execution instance id;
- issued and expiry timestamps;
- deterministic binding digest.

An external `binding_verifier` must confirm this binding through a trust mechanism outside the
OperationProof proof document. Missing, false, expired, tampered, or throwing verification fails
closed.

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

Three different properties remain separate:

1. `verify_proof()` verifies OperationProof structure, digests, semantics, and PRE/FINAL binding.
2. the CASER adapter validates and normalizes native receipt/verification claims plus trusted PRE binding.
3. `verify_proof_trust()` verifies provider authenticity using deployment-owned trust configuration.

A production sidecar should require all relevant gates. Native content identities, metadata strings,
or self-asserted provider names never establish trust roots.
