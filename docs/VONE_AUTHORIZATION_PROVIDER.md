# V-One authorization provider boundary

OperationProof treats V-One as an external authorization authority. OperationProof does not reimplement V-One policy, approval, capability, revocation, precondition, grant-consumption, or dispatch logic.

## Canonical provider artifacts

The authorization envelope is created from V-One `execution-grant/v2` for one OperationProof PRE operation.

`AuthorizationSnapshot` alone is intentionally insufficient for PASS. V-One documents the snapshot as immutable authorization evidence rather than an irrevocable bearer permission, and authoritative grant issuance re-checks live permission and deny gates. The grant therefore supplies the narrowed, short-lived authority artifact.

V-One consumes a `ONE_TIME` grant durably in the control plane before Dispatch. Its canonical post-consumption artifact is `grant-consumption-witness/v1`. OperationProof uses that witness only when an already-authorized PRE proof is revalidated as the embedded PRE of a FINAL proof.

These are deliberately different trust questions:

- **DIRECT PRE admission:** is this exact grant authentic, currently inside its issuance window, and still admissible/unused according to authoritative V-One state?
- **embedded PRE during FINAL verification:** was this exact grant durably consumed for this exact execution while the grant remains inside the authorization evidence lifetime?

A consumption witness never substitutes for unused-grant admission. A consumed grant is not accepted for a new DIRECT PRE operation. A consumption witness also does not extend the grant or PRE-evidence expiry window.

## Grant bindings

The adapter requires:

- exact V-One `execution-grant/v2` field set
- exact integer `schema_version == 2`
- `execution_id == OperationProof operation_id`
- `required_permission == execution.run`
- `use_semantics == ONE_TIME`
- supported V-One precondition enforcement class
- non-negative revocation epoch
- canonical UTC millisecond timestamps
- positive grant TTL no longer than 300 seconds
- precondition witness no more than 30 seconds before grant issuance
- verification time within `issued_at <= now < expires_at` for both DIRECT PRE and embedded PRE during FINAL provider verification
- valid provider-native lowercase 64-hex SHA-256 fields
- exact recomputation of V-One `grant_digest`
- an external trusted admission verifier returning true for DIRECT PRE

The adapter computes an additional OperationProof-local `sha256:` digest over the complete grant document. The V-One native digest remains provider evidence; neither digest is an authenticity root by itself.

## Evidence mapping

The resulting envelope uses:

- layer: `authorization`
- provider: `vone`
- decision: `execution-grant/v2`
- verdict: `PASS`
- issued/expires: exact V-One grant window

The subject digest binds the operation to the snapshot, actor, workspace, environment, capability, capability definition, target, and payload. The evidence digest binds the provider, exact OperationProof grant-document digest, and V-One native grant digest.

## Trusted verification stage

The R5.1 stage is internal OperationProof provider-trust state. It is **not** a field or property of the public six-field `TrustVerificationContext` and is never serialized in a proof.

- `DIRECT` is used when a PRE proof is verified directly.
- `EMBEDDED_PRE_OF_FINAL` is used when the exact embedded PRE of a structurally valid FINAL proof is recursively provider-verified.

OperationProof carries this stage only during the active provider callback through a private `ContextVar` invocation marker. The marker is revoked in-place before the callback scope closes, so an `asyncio` child task that copied the context cannot retain embedded-FINAL authority after the parent callback returns.

The stage marker does **not** replace or alter R3/R3.1 context isolation. Embedded PRE evidence still receives `root_phase=PRE`, `evidence_phase=PRE`, the PRE proof's own digest and operation id, and `pre_proof_digest=None`. An outer FINAL proof therefore cannot launder its digest or phase into PRE provider trust.

## DIRECT PRE provider trust

`make_vone_execution_grant_trust_verifier()` re-resolves the exact grant out of band by its OperationProof document digest, reproduces the exact serialized authorization envelope, and invokes `grant_verifier`.

`grant_verifier` is the deployment's admission authority. For a V-One `ONE_TIME` grant it must fail closed when the grant is already consumed, revoked, invalidated, or otherwise no longer admissible.

## Post-consumption provider trust inside FINAL

When the same PRE proof is revalidated inside a FINAL proof, the grant may legitimately already be consumed. OperationProof therefore does **not** re-run the unused-grant admission check in this stage.

Instead it requires both `consumption_resolver` and `consumption_verifier`. The resolver obtains authoritative V-One `grant-consumption-witness/v1` by grant JTI. The witness must have the exact V-One field contract, exact integer `schema_version == 1`, and bind:

- grant JTI and grant ID
- native grant digest
- execution ID / OperationProof operation ID
- authorization snapshot digest
- execution capsule digest
- runner class
- live revocation epoch equal to the grant epoch
- V-One conformance and clock witness digests
- canonical `consumed_at`
- `sqlite-begin-immediate/v1` serialization contract
- authority revision
- exact recomputed native witness digest

OperationProof additionally requires `issued_at <= consumed_at < expires_at` and `consumed_at <= verification time`.

The FINAL verifier still requires the current verification instant to be before `expires_at`. This matches the protocol invariant that the embedded PRE proof must remain structurally valid and its evidence unexpired. Historical verification after expiry would require a separate protocol/versioned archival-proof design; R5.1 does not invent one.

If the consumption resolver/verifier is absent, false, throws, returns the wrong witness, or any binding differs, FINAL provider trust fails closed.

## Trust roots and non-goals

Resolver configuration plus the external admission/consumption verifiers are deployment trust roots. They must never be learned from the proof, grant, envelope, or consumption witness itself.

OperationProof does not issue, revoke, consume, refresh, or dispatch V-One grants. It does not infer a consumption witness from execution success. Serialized OperationProof evidence is never the source of authority.
