from __future__ import annotations

from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .sdk import ProofDocumentError, assess_proof, parse_proof_json
from .trust import ProviderTrustRegistry

SIDECAR_CONTRACT = "operationproof.sidecar.v1"
DEFAULT_MAX_BODY_BYTES = 1024 * 1024
MAX_CONFIGURED_BODY_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SidecarConfig:
    require_trust: bool = True
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES


class SidecarConfigError(ValueError):
    """Raised when trusted sidecar deployment configuration is invalid."""


class SidecarRequestError(ValueError):
    """Raised for bounded, deterministic request-boundary failures."""

    def __init__(self, status_code: int, reason_code: str) -> None:
        super().__init__(reason_code)
        self.status_code = status_code
        self.reason_code = reason_code


def _validate_config(config: SidecarConfig) -> None:
    if not isinstance(config.require_trust, bool):
        raise SidecarConfigError("INVALID_REQUIRE_TRUST")
    if not isinstance(config.max_body_bytes, int) or isinstance(config.max_body_bytes, bool):
        raise SidecarConfigError("INVALID_MAX_BODY_BYTES")
    if not 1 <= config.max_body_bytes <= MAX_CONFIGURED_BODY_BYTES:
        raise SidecarConfigError("INVALID_MAX_BODY_BYTES")


def _headers() -> dict[str, str]:
    return {
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
    }


def _error_response(status_code: int, reason_code: str) -> JSONResponse:
    if len(reason_code) > 256:
        reason_code = "INVALID_PROOF_DOCUMENT"
    return JSONResponse(
        status_code=status_code,
        content={
            "contract": SIDECAR_CONTRACT,
            "accepted": False,
            "reason_codes": [reason_code],
        },
        headers=_headers(),
    )


def _content_length(request: Request) -> int | None:
    raw = request.headers.get("content-length")
    if raw is None:
        return None
    if not raw.isdecimal():
        raise SidecarRequestError(400, "INVALID_CONTENT_LENGTH")
    try:
        value = int(raw)
    except (ValueError, OverflowError) as exc:
        raise SidecarRequestError(400, "INVALID_CONTENT_LENGTH") from exc
    if value < 0:
        raise SidecarRequestError(400, "INVALID_CONTENT_LENGTH")
    return value


async def _read_bounded_body(request: Request, max_body_bytes: int) -> bytes:
    declared = _content_length(request)
    if declared is not None and declared > max_body_bytes:
        raise SidecarRequestError(413, "REQUEST_BODY_TOO_LARGE")

    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > max_body_bytes:
                raise SidecarRequestError(413, "REQUEST_BODY_TOO_LARGE")
            body.extend(chunk)
    except SidecarRequestError:
        raise
    except Exception as exc:  # noqa: BLE001 - network boundary must fail closed
        raise SidecarRequestError(400, "REQUEST_BODY_READ_FAILED") from exc

    if declared is not None and len(body) != declared:
        raise SidecarRequestError(400, "CONTENT_LENGTH_MISMATCH")
    return bytes(body)


def create_app(
    registry: ProviderTrustRegistry | None = None,
    *,
    require_trust: bool = True,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> FastAPI:
    """Create the OperationProof sidecar application from trusted deployment config.

    The provider registry is injected out-of-band at process startup. No HTTP route can
    add, replace, or mutate provider trust entries.
    """

    if registry is not None and not isinstance(registry, ProviderTrustRegistry):
        raise SidecarConfigError("INVALID_TRUST_REGISTRY")
    config = SidecarConfig(
        require_trust=require_trust,
        max_body_bytes=max_body_bytes,
    )
    _validate_config(config)

    app = FastAPI(
        title="OperationProof Sidecar",
        version="v1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_request: Request, _exc: Exception) -> JSONResponse:
        return _error_response(500, "INTERNAL_RUNTIME_ERROR")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse(
            status_code=200,
            content={
                "contract": SIDECAR_CONTRACT,
                "status": "alive",
            },
            headers=_headers(),
        )

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        if config.require_trust and registry is None:
            return _error_response(503, "TRUST_REGISTRY_REQUIRED")
        mode = "trusted" if registry is not None else "integrity-only"
        return JSONResponse(
            status_code=200,
            content={
                "contract": SIDECAR_CONTRACT,
                "ready": True,
                "mode": mode,
            },
            headers=_headers(),
        )

    @app.post("/v1/assess")
    async def assess(request: Request) -> JSONResponse:
        if config.require_trust and registry is None:
            return _error_response(503, "TRUST_REGISTRY_REQUIRED")

        media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            return _error_response(415, "UNSUPPORTED_MEDIA_TYPE")

        content_encoding = request.headers.get("content-encoding")
        if content_encoding is not None and content_encoding.strip().lower() not in {"", "identity"}:
            return _error_response(415, "UNSUPPORTED_CONTENT_ENCODING")

        try:
            raw = await _read_bounded_body(request, config.max_body_bytes)
        except SidecarRequestError as exc:
            return _error_response(exc.status_code, exc.reason_code)
        if not raw:
            return _error_response(400, "EMPTY_REQUEST_BODY")

        try:
            proof = parse_proof_json(raw)
        except ProofDocumentError as exc:
            return _error_response(400, str(exc))

        assessment = assess_proof(proof, registry=registry)
        return JSONResponse(
            status_code=200,
            content={
                "contract": SIDECAR_CONTRACT,
                "assessment": assessment.to_dict(),
            },
            headers=_headers(),
        )

    return app
