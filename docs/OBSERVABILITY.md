# OP-R11 Observability

## Two different channels

R11 deliberately separates security provenance from operational telemetry.

### Required provenance

Cryptographically bound attestations stored through `AttestationStore`.

A deployment may mark this channel required. When required persistence fails, the governed path fails closed where execution has not yet occurred. If the external side effect has already happened, OperationProof reports provenance failure and never fabricates a proof rollback.

### Best-effort telemetry

Structured metrics/log export through `TelemetrySink`.

Telemetry export failure is swallowed by `emit_telemetry_best_effort()`. It cannot:

- turn a valid proof into a failed proof,
- turn a failed proof into PASS,
- create provenance evidence,
- authorize execution.

## Event schema

`operationproof.observability-event.v1` is machine-readable and contains only bounded identifiers, digests, state transitions, reason codes, and timestamps.

Supported R11 lifecycle events:

- `proof_assessed`
- `admission_created`
- `admission_consumed`
- `upstream_dispatch_prepared`
- `upstream_dispatched`
- `upstream_completed`
- `upstream_failed`
- `execution_receipt_verified`
- `final_proof_composed`

`upstream_dispatch_prepared` is a durable pre-network barrier. After it persists, the gateway performs another admission-expiry check immediately before opening the upstream stream. `upstream_dispatched` is emitted only after the upstream stream has actually been entered. This separation prevents slow provenance persistence from weakening the R10 freshness invariant or falsely claiming that an expired request was sent.

Raw request bodies, response bodies, admission tokens, provider secrets, signing keys, and raw evidence payloads are not event fields by default.

Each event has an `event_digest`. The corresponding attestation uses that event digest as `payload_digest`, creating an explicit machine-verifiable link between telemetry semantics and persisted provenance without making telemetry itself authoritative.

## Gateway policy

`create_attested_gateway_app()` implements:

```text
provenance policy = required
telemetry policy  = best-effort
```

Use the canonical R10 `create_gateway_app()` when provenance is not configured. Its optional pre-dispatch hook defaults to `None`; R11 owns that hook only when the attested gateway composition is explicitly selected. Do not silently substitute best-effort logs for an R11 provenance store.

## Deployment requirements

Production deployments should supply at startup/out-of-band:

- trusted PRE provider registry,
- durable R10 admission store,
- `AttestationSigner`,
- matching explicit `AttestationVerifier`,
- durable `AttestationStore`,
- optional `TelemetrySink`,
- fixed upstream client/configuration.

The caller owns the lifecycle of the injected `httpx.AsyncClient`; R11 does not silently replace or close a caller-owned client.

Client HTTP input must never select any of these trust components or the R11 pre-dispatch hook.
