# OperationProof Protocol

## Evidence envelope

Every provider is normalized to `operationproof.evidence-envelope.v1`.

Canonical fields:

- `layer`
- `provider`
- `operation_id`
- `decision`
- `verdict`
- `subject_digest`
- `evidence_digest`
- `issued_at`
- optional `expires_at`
- optional `metadata`

`decision` preserves the provider-native vocabulary. `verdict` is the OperationProof normalization used for composition.

## Proof versions

`operationproof.operation-proof.v1` remains verifiable for backward compatibility. It binds layers to one `operation_id`, but does not establish that every provider means the same actor / intent / target / state subject.

`operationproof.operation-proof.v2` is the canonical R6 subject-bound protocol. New composed proofs should use v2.

## Canonical OperationSubject

A v2 proof embeds one `operationproof.operation-subject.v1`:

```text
operation_id
actor_digest
intent_digest
target_digest
state_digest
```

The four component digests are provider-neutral opaque identities. Provider adapters remain responsible for proving that their native vocabulary maps to those same dimensions.

`subject_digest` is the SHA-256 digest of the exact canonical OperationSubject document. A v2 proof can be `VERIFIED` only when every evidence envelope in scope carries that exact same `subject_digest`.

This prevents evidence composition across different actors, intentions, targets, or pre-operation states even when all provider-local verdicts individually say `PASS`.

## PRE phase

Required layers:

```text
identity
authorization
intent
continuity
tool_safety
data_flow
resource
```

A v1 PRE proof is `VERIFIED` only if every required layer is present exactly once, belongs to the same operation, is unexpired, and has normalized verdict `PASS`.

A v2 PRE proof additionally requires exact `subject_digest` equality across all seven required layers.

## FINAL phase

A FINAL proof requires:

1. an embedded, structurally and cryptographically valid PRE proof;
2. `pre_proof_digest` matching that exact embedded PRE proof;
3. PRE decision `VERIFIED`;
4. execution evidence bound to the same operation;
5. execution verdict `PASS`.

For v2, FINAL additionally carries the exact same embedded `subject` and `subject_digest` as PRE, and execution evidence must carry that same canonical `subject_digest`.

## Integrity versus semantic decision

A subject mismatch is a semantic rejection, not necessarily a malformed proof. A correctly recorded v2 proof may therefore be integrity-valid while its decision is `REJECTED` with a reason such as `SUBJECT_DIGEST_MISMATCH:intent`.

Tampering with the embedded `subject` or its claimed `subject_digest`, by contrast, is an integrity failure.

## Canonicalization

OperationProof uses UTF-8 JSON with sorted keys and compact separators. `proof_digest` is excluded from its own digest input.

Digest format:

```text
sha256:<64 lowercase hexadecimal characters>
```
