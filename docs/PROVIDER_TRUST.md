# Provider Trust Gate

## Why this exists

`verify_proof()` proves that an OperationProof is canonically well-formed, internally consistent,
and deterministically bound by its digests. That is necessary but it is not provider authenticity.
A caller can otherwise construct a syntactically valid `EvidenceEnvelope` and claim a provider name.

R3 adds a second, explicit gate:

```text
verify_proof()        -> structural integrity / deterministic semantics
verify_proof_trust()  -> provider authenticity / trusted deployment policy
```

A proof is acceptable for governed execution only when both gates succeed.

## ProviderTrustRegistry

The trust registry is trusted deployment configuration keyed by the exact pair:

```text
(layer, provider)
```

Examples:

```text
(continuity, howedo)
(identity, spiffe)
(authorization, vone)
(execution, sandcloud)
```

Each entry supplies an external verifier for the exact serialized evidence envelope. The verifier may
validate a signature or attestation, query a trusted receipt store, validate a provider response, or
perform another provider-specific authenticity check.

The registry **must not** be populated from provider names, keys, URLs, booleans, or trust metadata
carried inside the proof being verified. Doing so would let untrusted input define its own trust root.

## Trusted proof context

Provider verifiers receive two inputs:

```text
(envelope, TrustVerificationContext)
```

The context is derived only after the outer proof passes structural verification and contains:

- `root_phase`
- `evidence_phase`
- exact outer `operation_id`
- exact outer `proof_digest`
- exact `pre_proof_digest` for FINAL proofs
- stable `evidence_index`

This is required for execution providers. A SandCloud/CASER verifier must be able to prove that a
receipt belongs not merely to an operation ID, but to the exact PRE proof that authorized execution.
It should compare the provider-authenticated receipt binding against `context.pre_proof_digest`, not
against a pre-proof digest asserted only inside untrusted evidence metadata.

## Fail-closed invariants

- no registered `(layer, provider)` verifier -> reject
- verifier returns anything other than literal `True` -> reject
- verifier raises -> reject
- structurally invalid proof -> reject before provider trust evaluation
- proof decision `REJECTED` -> provider trust never promotes it to `VERIFIED`
- FINAL proof recursively requires trusted PRE evidence and trusted execution evidence
- duplicate registry entries cannot silently replace an existing verifier
- proof context comes from the structurally verified outer proof, never from provider-controlled metadata

## HOWEDO R2 interaction

The R2 HOWEDO adapter verifies the native witness and requires an externally verified operation/freshness
binding while collecting continuity evidence. R3 closes the serialized-proof gap at consumption time:
a deployment can register a HOWEDO evidence verifier that re-checks the attestation, trusted receipt
store, or other authoritative mapping referenced by the exact continuity envelope.

A locally valid digest or metadata string such as `binding=verified` is never sufficient by itself.

## Sidecar model

```text
Agent / App
    |
    v
OperationProof sidecar
    |
    +-- verify_proof()          canonical integrity
    |
    +-- ProviderTrustRegistry   trusted out-of-band config
    |       |
    |       +-- HOWEDO verifier
    |       +-- V-One verifier
    |       +-- SPIFFE verifier
    |       +-- SandCloud verifier
    |
    +-- verify_proof_trust()
            |
            +-- TRUSTED -> eligible for next gate
            +-- REJECTED -> fail closed
```

The core performs no network I/O and does not prescribe PKI. Provider verifiers remain pluggable so
future adapters can use established systems such as Sigstore/in-toto, SPIFFE/SPIRE, OIDC/JWS, or a
trusted local receipt database without changing OperationProof's canonical evidence model.

## Non-goals

R3 does not make OperationProof self-contained or offline-verifiable. A fully portable signed proof
bundle is a later protocol layer. R3 establishes the runtime trust boundary required before additional
provider adapters, especially execution providers, can safely be treated as authoritative.
