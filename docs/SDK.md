# OperationProof SDK contract

R7 introduces the stable public library facade `operationproof.sdk.v1`.

## Why the facade exists

The low-level verifier deliberately distinguishes proof integrity from proof semantics and provider authenticity. In particular:

```text
verify_proof(proof).valid == True
```

means that the serialized proof is internally consistent. It does **not** mean that the operation is trusted or authorized to proceed.

The SDK therefore exposes a fail-closed assessment result with three separate gates:

```text
integrity_valid
    AND decision == VERIFIED
    AND trusted == True
        => accepted == True
```

If no `ProviderTrustRegistry` is supplied, trust is not guessed. The assessment returns:

```text
trust_evaluated = False
trusted = None
accepted = False
SDK:TRUST_NOT_EVALUATED
```

## Public API

The supported R7 public facade is exported from the package root:

```python
from operationproof import (
    ProofAssessment,
    ProofDocumentError,
    SDK_CONTRACT,
    assess_proof,
    assess_proof_json,
    canonical_proof_json,
    parse_proof_json,
)
```

`operationproof.__all__` is regression-tested as an API contract. Adding, removing, or renaming a public export must therefore be an intentional reviewed change.

## Structured assessment

```python
assessment = assess_proof(proof, registry=trust_registry)

if assessment.accepted:
    execute_governed_operation()
```

`ProofAssessment` reports:

- proof schema, phase, and operation id;
- `integrity_valid`;
- recorded semantic `decision`;
- whether provider trust was evaluated;
- provider trust result;
- fail-closed `accepted` result;
- separate integrity, trust, and SDK reason-code namespaces.

The SDK never promotes an integrity-only result to governed acceptance.

## Strict raw JSON boundary

Use `parse_proof_json()` or `assess_proof_json()` for untrusted serialized input.

The parser rejects:

- duplicate JSON object keys at any nesting level;
- non-finite JSON numbers (`NaN`, `Infinity`, `-Infinity`);
- non-UTF-8 byte input;
- non-object top-level documents;
- malformed JSON.

This avoids parser ambiguity before canonical proof verification begins.

`assess_proof_json()` converts parse failure into a fail-closed `ProofAssessment` rather than raising. `parse_proof_json()` raises `ProofDocumentError` when callers need explicit parser error handling.

## Canonical serialization

`canonical_proof_json()` uses the same sorted-key, compact UTF-8 JSON representation as OperationProof digest canonicalization. It is suitable for deterministic transport/storage representation; it does not add trust or signatures.

## Caller-mutation boundary

`assess_proof()` snapshots the supplied proof before integrity and trust verification. Provider verifier callbacks therefore cannot mutate the caller-owned proof through the SDK verification path.

The snapshot does not change provider authority semantics. Provider verifiers and the out-of-band `ProviderTrustRegistry` remain the source of authenticity decisions.

## Compatibility

R7 is additive:

- `verify_proof()` remains the low-level integrity verifier;
- `verify_proof_trust()` remains the provider-authenticity verifier;
- `build_pre_proof()` and `build_final_proof()` retain their existing contracts;
- proof v1 remains readable;
- proof v2 / canonical OperationSubject remains the preferred subject-bound protocol.

Existing callers do not need to migrate immediately. New governed integrations should prefer `assess_proof(..., registry=...)` so integrity cannot be confused with acceptance.
