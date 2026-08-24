# OperationProof R11 — signed provenance, observability, and attestations

R11 adds cryptographic provenance and tamper-evident observability without changing OperationProof governance semantics.

## Non-negotiable boundary

A valid signature is not an authorization decision.

```text
proof integrity   != provider trust
provider trust    != execution authorization
signature valid   != proof VERIFIED
telemetry emitted != execution succeeded
```

Attestations prove that a trusted signing key signed an exact canonical provenance statement. They do not upgrade a rejected, malformed, stale, or untrusted proof into an accepted operation.

## Provenance statement

`operationproof.provenance-statement.v1` binds:

- `operation_id`;
- canonical `subject_digest`;
- artifact type;
- exact artifact digest;
- producer identity label;
- RFC3339 issue time;
- optional predecessor attestation digest;
- canonical metadata;
- `statement_digest`.

First-party helpers are provided for integrity-valid v2 PRE/FINAL proofs and valid execution receipts. Generic statements support gateway admission/forward and future artifact types without changing proof semantics.

## Signed attestation

`operationproof.signed-attestation.v1` contains the exact provenance statement plus:

- canonical `statement_digest`;
- signature algorithm;
- explicit `key_id`;
- detached signature bytes encoded as URL-safe base64;
- canonical `attestation_digest`.

The signature input is domain-separated from ordinary application data before canonical statement bytes are signed.

R11 ships an Ed25519 reference signer and trusted public-key registry behind the optional `operationproof[attestations]` dependency. The base SDK remains crypto-backend-free.

## Chain verification

`verify_attestation_chain()` requires every member to be individually trusted and additionally enforces:

- one exact `operation_id` across the chain;
- one exact `subject_digest` across the chain;
- first member has no predecessor;
- each later member's `predecessor_attestation_digest` equals the prior exact `attestation_digest`;
- no duplicate attestation digest.

This prevents a valid attestation from another operation or subject being spliced into a provenance chain.

A typical chain is:

```text
PRE proof attestation
        |
        v
Gateway admission/forward attestation
        |
        v
Execution receipt attestation
        |
        v
FINAL proof attestation
```

R11 defines the portable chain contract. It does not require one deployment to use every artifact type.

## Observability

`operationproof.observability-event.v1` is a canonical tamper-evident event envelope with:

- event type;
- RFC3339 occurrence time;
- operation ID;
- optional subject/artifact/attestation digests;
- outcome;
- bounded reason codes;
- canonical attributes;
- event digest.

The in-memory sink is a bounded reference implementation that deep-snapshots caller-owned events before storing them.

`assess_proof_observed()` returns both the normal SDK `ProofAssessment` and an independent telemetry emission result. Sink failure cannot change `ProofAssessment.accepted`.

This is deliberate: deployments that require durable audit delivery before execution must enforce that requirement as explicit deployment policy. OperationProof does not silently rewrite authorization semantics because an observability backend is unavailable.

## Key management boundary

OperationProof does not generate, persist, rotate, distribute, or escrow production signing keys. Deployments must provide those controls through their KMS/HSM/secret-management boundary. `key_id` is an external trust locator, not secret key material.

Private key bytes must never be placed in proof metadata, observability events, repository files, or attestation documents.

## Verification order

For a signed proof artifact, the safe order is:

1. strictly parse the proof document;
2. verify OperationProof proof integrity;
3. evaluate provider trust where governed acceptance is needed;
4. verify provenance statement digest;
5. verify signed-attestation digest;
6. resolve the exact `(algorithm, key_id)` verifier;
7. verify the signature;
8. verify predecessor/operation/subject chain binding when a chain is supplied.

No step can compensate for failure in an earlier semantic layer.
