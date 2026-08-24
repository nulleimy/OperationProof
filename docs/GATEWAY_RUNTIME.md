# OperationProof gateway mode

R10 adds an active enforcement gateway on top of the R7 SDK, R8 runtime hardening, and R9 provider contracts.

Gateway mode is intentionally stricter than sidecar assessment mode. It never has an integrity-only operating mode: forwarding is possible only after a trusted `operationproof.operation-proof.v2` PRE proof is accepted by the SDK and admitted through a replay boundary.

## Flow

```text
client
  |
  | POST /v1/admissions  (trusted PRE/v2 proof)
  v
OperationProof gateway
  |  strict JSON + integrity + semantics + provider trust
  |  require expiry on every PRE evidence envelope
  |  atomically reserve proof_digest
  v
one-time admission token
  |
  | request /v1/proxy/<path> + token
  v
consume token exactly once
  |
  | recompute operationproof.gateway-target.v1 from the real request
  | require target.digest == OperationSubject.target_digest
  v
fixed startup-configured upstream
```

The token is consumed before target comparison. A mismatched or malformed proxy attempt therefore burns the token rather than leaving it reusable.

## Canonical gateway target

A proof author binds the exact intended HTTP operation by putting `gateway_target_digest(...)` into `OperationSubject.target_digest`.

```python
from operationproof import gateway_target_digest

body = b'{"release":"2026.08"}'
target_digest = gateway_target_digest(
    upstream_id="deployment-api",
    method="POST",
    path="/releases",
    query="dry=0",
    headers={"content-type": "application/json"},
    body=body,
)
```

The canonical `operationproof.gateway-target.v1` includes:

- operator-controlled `upstream_id`;
- HTTP method;
- canonical path;
- exact raw query string;
- digest of the configured forwarded-header set and values;
- SHA-256 digest of the raw body.

Path traversal segments (`.` / `..`), backslashes, fragments, invalid control characters, hop-by-hop headers, and all client-supplied `x-operationproof-*` headers are rejected.

## Replay boundary

`GatewayAdmissionStore` is the runtime replay contract:

```python
class MyDurableStore(GatewayAdmissionStore):
    def reserve(self, record): ...  # atomic proof_digest uniqueness + opaque token
    def consume(self, token): ...   # atomic one-time consume
```

Production runtime requires `--admission-store-factory module:factory`. The factory must return a `GatewayAdmissionStore` implementation whose `reserve()` operation is atomic across all gateway instances that share an authorization domain.

`MemoryGatewayAdmissionStore` is a single-process reference implementation. It retains proof digests for the process lifetime and never evicts replay history; capacity exhaustion fails closed. It is available at runtime only through the explicit `--allow-ephemeral-admission-store` flag and is not a durable multi-instance replay boundary.

## Freshness

Gateway admission requires `expires_at` on every PRE evidence envelope. The one-time admission expiry is the earlier of:

1. the earliest evidence expiry; or
2. the configured admission TTL (default 30 seconds, maximum 300 seconds).

This is stricter than the core proof format, where an envelope may omit expiry. Active forwarding therefore cannot turn non-expiring evidence into a reusable gateway capability.

## Upstream boundary

The upstream base URL and stable `upstream_id` are supplied only at process startup. No HTTP request field selects a hostname, scheme, port, or upstream identity. Redirects are not followed.

Only an operator-configured header allowlist is forwarded. By default that is `content-type` only. The gateway strips client authority over internal metadata and injects its own:

```text
x-operationproof-gateway-contract
x-operationproof-operation-id
x-operationproof-proof-digest
x-operationproof-subject-digest
```

Upstream response bodies are bounded before being returned. The gateway forwards only the upstream status, body, and `content-type`; response `server`, cookies, redirects, and other headers are not automatically propagated.

## Runtime

Install the optional runtime:

```bash
python -m pip install -e '.[gateway]'
```

Production-style bootstrap:

```bash
operationproof-gateway \
  --trust-factory mydeployment.trust:build_registry \
  --admission-store-factory mydeployment.replay:build_store \
  --upstream-base-url https://internal-api.example \
  --upstream-id deployment-api
```

The process defaults to `127.0.0.1:8081`, disables proxy-derived client metadata, suppresses server/date headers, and uses one Uvicorn worker. External exposure, TLS/mTLS, service identity, network policy, and load-balancer configuration remain deployment responsibilities rather than being self-asserted by OperationProof.

## Endpoints

- `GET /healthz` — process liveness only.
- `GET /readyz` — configured trusted gateway runtime.
- `POST /v1/admissions` — strict trusted PRE/v2 proof admission.
- `GET|POST|PUT|PATCH|DELETE /v1/proxy/{path}` — one-time target-bound forwarding.

## Security boundary

Gateway admission means the supplied PRE proof was integrity-valid, semantically `VERIFIED`, provider-trusted, v2 subject-bound, fresh enough for gateway admission, and successfully reserved against replay. It does not claim that the eventual upstream execution succeeded. Execution outcome and provider post-state remain R4/CASER + FINAL-proof responsibilities.
