# OperationProof Constitution

## Mission

OperationProof produces reproducible evidence that one exact operation passed the required independent control layers before execution and that the resulting execution can be bound back to that authorization after execution.

## Product boundary

OperationProof owns evidence normalization, binding, deterministic composition, proof integrity, verification semantics, and provider conformance boundaries.

It does **not** own identity issuance, authorization policy, intent interpretation, continuity semantics, tool enforcement, DLP classification, resource accounting, sandbox execution, generic observability, or generic lineage storage.

## Canonical evidence layers

1. Identity
2. Authorization
3. Intent
4. Continuity
5. Tool Safety
6. Data Flow
7. Resource
8. Execution

## Phases

- `PRE`: layers 1-7 are evaluated before execution.
- `FINAL`: a cryptographically bound verified PRE proof plus execution evidence forms the final proof.

## Non-negotiable invariants

I1. Every evidence envelope binds to one exact `operation_id`.
I2. Every authoritative payload is content-addressed with SHA-256.
I3. Missing evidence never implies success.
I4. `UNKNOWN` never implies success.
I5. A failed layer cannot be overridden by another successful layer.
I6. Duplicate evidence for one canonical layer is rejected unless a future protocol explicitly defines quorum semantics.
I7. Execution evidence cannot authorize its own execution.
I8. A FinalOperationProof must bind to the exact verified PreOperationProof that authorized execution.
I9. Provider-specific semantics cannot mutate OperationProof core semantics.
I10. LLM judgment cannot directly promote a proof to `VERIFIED`.
I11. Proof verification must be reproducible from canonical recorded inputs.
I12. V-One is an optional authorization provider, not part of OperationProof core.

## Change policy

Changes to layer identities, phase semantics, canonicalization, digest rules, proof decisions, or invariants require an ADR and compatibility review.
