# OperationProof sidecar runtime

R8 adds an optional HTTP sidecar around the R7 SDK without changing proof, trust, or provider authority semantics.

## Contract

The runtime contract is `operationproof.sidecar.v1`.

Endpoints:

- `GET /healthz` — process liveness only. It can be healthy even when trusted assessment is not ready.
- `GET /readyz` — deployment readiness. Default trusted mode returns `503` until a `ProviderTrustRegistry` is injected at startup.
- `POST /v1/assess` — strict raw JSON proof assessment using the same R7 SDK gates.

Interactive API docs and runtime OpenAPI endpoints are disabled.

## Install

```bash
python -m pip install -e '.[sidecar]'
```

The core SDK deliberately does not depend on FastAPI or Uvicorn. Sidecar dependencies are opt-in.

## Trusted startup

The default runtime requires an out-of-band zero-argument registry factory:

```python
# mydeployment/trust.py
from operationproof import ProviderTrustRegistry


def build_registry() -> ProviderTrustRegistry:
    registry = ProviderTrustRegistry()
    # Register trusted provider verifiers here.
    return registry
```

Run:

```bash
operationproof-sidecar \
  --trust-factory mydeployment.trust:build_registry
```

The factory module is deployment configuration and is never derived from an OperationProof request. There is no HTTP endpoint for registering or replacing provider trust verifiers.

## Integrity-only escape hatch

For diagnostics only, an operator may start:

```bash
operationproof-sidecar --allow-integrity-only
```

This is explicit. Without a registry, `ProofAssessment.accepted` remains `false` and includes `TRUST_NOT_EVALUATED`; integrity-only mode never becomes governed acceptance.

## Network boundary

The default bind address is `127.0.0.1`. R8 is a sidecar, not a public gateway. It does not add TLS, mTLS, authentication, rate limiting, or reverse-proxy trust. Remote exposure belongs behind an external authenticated network boundary and later gateway work.

Runtime defaults also disable proxy-header trust, server/date response headers, and multi-worker execution.

## Request boundary

`POST /v1/assess` accepts only `application/json` with no content encoding other than `identity`.

The request body is bounded while streaming. Default maximum size is 1 MiB and trusted configuration cannot raise it above 16 MiB. Both declared `Content-Length` and actual streamed bytes are checked. Compressed request bodies are rejected instead of being decompressed inside the sidecar.

Malformed JSON returns a deterministic fail-closed HTTP error. Valid JSON that represents an invalid, rejected, or untrusted proof returns a normal assessment response with `accepted=false`.

## Readiness semantics

Trusted mode:

```text
registry present     -> /readyz 200
registry missing     -> /readyz 503 TRUST_REGISTRY_REQUIRED
```

Explicit integrity-only mode:

```text
registry absent      -> /readyz 200 mode=integrity-only
/v1/assess           -> accepted=false unless provider trust is actually evaluated
```

`/healthz` never claims that trust configuration is ready; it reports process liveness only.

## Runtime command controls

```text
--host                 default 127.0.0.1
--port                 default 8080
--trust-factory        module:callable trusted bootstrap
--allow-integrity-only explicit diagnostic mode
--max-body-bytes       default 1048576
--limit-concurrency    default 100
--timeout-keep-alive   default 5
--log-level            critical|error|warning|info
```

The runtime uses one worker because provider verifier registries are process-local trusted objects and R8 does not yet define multi-process registry lifecycle or synchronization semantics.
