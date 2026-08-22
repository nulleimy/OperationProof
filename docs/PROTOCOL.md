# OperationProof Protocol v1

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

A PRE proof is `VERIFIED` only if every required layer is present exactly once, belongs to the same operation, is unexpired, and has normalized verdict `PASS`.

## FINAL phase

A FINAL proof requires:

1. a structurally and cryptographically valid PRE proof;
2. PRE decision `VERIFIED`;
3. execution evidence bound to the same operation;
4. execution verdict `PASS`.

## Canonicalization

R0-R1 uses UTF-8 JSON with sorted keys and compact separators. `proof_digest` is excluded from its own digest input.

Digest format:

```text
sha256:<64 lowercase hexadecimal characters>
```
