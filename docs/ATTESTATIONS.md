# OP-R11 Attestations and Signed Provenance

## Authority boundary

R11 adds cryptographically verifiable provenance. It does **not** add execution authority.

These are separate facts:

```text
provider/local ALLOW
!= OperationProof VERIFIED
!= V-One AUTHORIZED
!= signed attestation
```

A signature proves authenticity/integrity only under an explicitly supplied trust contract. It never changes `ProofDecision`, never upgrades `UNKNOWN`, `MISSING`, or `UNVERIFIED`, and never self-authorizes execution.

## Canonical attestation

`operationproof.attestation.v1` binds:

- `attestation_id`
- `operation_id`
- `subject_digest`
- `proof_digest` (the PRE proof anchor for one lifecycle)
- `artifact_type`
- `artifact_digest`
- `issuer_id`
- `issued_at`
- `sequence`
- `previous_attestation_digest` or `GENESIS`
- `payload_digest`
- `attestation_digest`

Canonical JSON uses the same sorted/minified UTF-8 serialization as the proof kernel. `attestation_digest` is `sha256:<hex>` over the canonical object with `attestation_digest` removed.

The PRE proof digest remains the chain anchor through gateway execution and FINAL composition. Later artifacts such as an execution receipt or FINAL proof are bound through `artifact_digest`. This prevents a later artifact from silently replacing the PRE authority context.

## Signature contract

`operationproof.signed-attestation.v1` contains the immutable attestation snapshot plus `operationproof.attestation-signature.v1`.

The signature envelope binds:

- algorithm id
- issuer id
- key id
- exact attestation digest
- signature bytes encoded by the adapter

`AttestationSigner` and `AttestationVerifier` are explicit external boundaries. OperationProof contains no global trust root and does not discover keys from untrusted attestation input.

The built-in `HMACSHA256Signer` / `HMACSHA256Verifier` pair is a symmetric reference/test authenticator. It proves integrity/authenticity to holders of the shared key; it is not a non-repudiation mechanism, not a production trust root, and is never automatically trusted. Production deployments should inject their own KMS/HSM-backed signer/verifier adapter as required by their trust model.

## Public SDK

```python
from operationproof import (
    build_attestation,
    canonical_attestation_json,
    sign_attestation,
    verify_attestation_integrity,
    verify_attestation_signature,
    verify_provenance_chain,
)
```

All verification APIs return typed result objects with explicit `reason_codes`; they do not return a bare authority boolean.

## Provenance chain

Every operation chain starts at sequence `0` with `previous_attestation_digest="GENESIS"`. Every later record must:

1. increment sequence exactly by one,
2. point to the exact predecessor digest,
3. retain the same `operation_id`,
4. retain the same `subject_digest`,
5. retain the same PRE `proof_digest`,
6. use a unique attestation id and digest,
7. verify under an explicitly provided signer/verifier trust mapping.

`verify_provenance_chain()` rejects cross-operation transplant, subject transplant, proof substitution, reordering, duplicate sequence positions, predecessor breaks, replayed ids/digests, future timestamps, and untrusted signer tuples.

## Store contract

`AttestationStore` is provider-neutral. Production adapters must durably and atomically enforce:

- expected next sequence,
- expected predecessor digest,
- attestation id uniqueness,
- attestation digest uniqueness,
- immutable operation/subject/PRE-proof anchor.

`MemoryAttestationStore` is only a single-process test/dev reference implementation.

External store outputs are runtime-validated. After append, `ProvenanceRecorder` performs a required read-back, re-verifies the signature, and requires canonical equality with the object it submitted. A store returning a mutated head, missing/mutated read-back, wrong digest, wrong sequence, wrong operation, wrong subject, or wrong proof anchor fails closed.

## Gateway lifecycle

R11 extends the R10 gateway with one optional startup-only pre-dispatch hook. The hook defaults to `None`; existing R10 callers retain the same authority model. When R11 is enabled through `operationproof.attested_gateway.create_attested_gateway_app()`, the hook is controlled exclusively by the R11 composition layer.

Required provenance events are:

```text
proof_assessed
→ admission_created
→ admission_consumed
→ upstream_dispatch_prepared
→ upstream_dispatched
→ upstream_completed | upstream_failed
```

`upstream_dispatch_prepared` is a durable pre-dispatch barrier. After it is persisted, the gateway rechecks admission expiry immediately before any network dispatch. `upstream_dispatched` is emitted only after the underlying upstream stream has actually been entered. This prevents a slow provenance write from reopening the R10 expiry TOCTOU window and prevents provenance from falsely claiming that network dispatch occurred when freshness rejected the request.

The wrapper preserves R10 semantics:

- PRE/v2 trusted admission remains required,
- one-time token replay semantics remain owned by the R10 admission store,
- token consumption still occurs before target verification,
- target mismatch still burns the token,
- expiry is rechecked after request reconstruction and again after the R11 pre-dispatch barrier,
- upstream remains startup-fixed,
- request/response bounds remain unchanged,
- no request can supply signer, verifier, issuer, key id, provenance store, telemetry sink, or pre-dispatch hook.

If required provenance persistence fails before admission, admission fails. If it fails after token consumption, the token remains burned. If the pre-dispatch barrier succeeds but the admission expires before network dispatch, the gateway returns `ADMISSION_TOKEN_EXPIRED`, performs no upstream I/O, and the token remains burned. If post-dispatch or completion provenance fails after an upstream side effect, OperationProof cannot undo the side effect; it fails the response path closed and records no false success claim.

## Execution and FINAL integration

`attest_execution_receipt()` first runs `verify_execution_receipt()`. A signature cannot turn an unverified execution receipt into execution PASS.

`attest_final_proof()` first runs core `verify_proof()` integrity verification and records the FINAL proof digest as an artifact. The FINAL proof's semantic `decision` is preserved only as a reason-coded state fact. Provenance validity does not rewrite that decision.

## Replay and freshness

Future `issued_at` values fail verification unless the caller deliberately configures a bounded skew. Replayed attestation ids or digests fail chain verification, and atomic stores must reject replay at persistence time as well.
