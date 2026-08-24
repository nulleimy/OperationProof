from __future__ import annotations

import hmac
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .canonical import valid_digest
from .gateway_contract import (
    GatewayTargetError,
    build_gateway_target,
    canonical_gateway_headers,
)
from .gateway_store import (
    GatewayAdmissionRecord,
    GatewayAdmissionStore,
    GatewayAdmissionStoreError,
)
from .rfc3339 import compare_timestamps, parse_rfc3339, timestamp_from_datetime
from .sdk import ProofDocumentError, assess_proof, parse_proof_json
from .trust import ProviderTrustRegistry

GATEWAY_CONTRACT = "operationproof.gateway.v1"
DEFAULT_MAX_PROOF_BYTES = 1024 * 1024
DEFAULT_MAX_PROXY_BODY_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_CONFIGURED_BODY_BYTES = 16 * 1024 * 1024
_ADMISSION_HEADER = "x-operationproof-admission"
_INTERNAL_PREFIX = "x-operationproof-"


class GatewayConfigError(ValueError):
    """Raised when gateway deployment configuration is unsafe or ambiguous."""


class GatewayRequestError(ValueError):
    """Raised for deterministic fail-closed request-boundary errors."""

    def __init__(self, status_code: int, reason_code: str) -> None:
        super().__init__(reason_code)
        self.status_code = status_code
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    upstream_base_url: str
    upstream_id: str
    max_proof_bytes: int = DEFAULT_MAX_PROOF_BYTES
    max_proxy_body_bytes: int = DEFAULT_MAX_PROXY_BODY_BYTES
    max_upstream_response_bytes: int = DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES
    admission_ttl_seconds: int = 30
    upstream_timeout_seconds: float = 10.0
    forward_headers: tuple[str, ...] = ("content-type",)


def _security_headers() -> dict[str, str]:
    return {
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
    }


def _error_response(status_code: int, reason_code: str) -> JSONResponse:
    if not isinstance(reason_code, str) or not reason_code or len(reason_code) > 256:
        reason_code = "GATEWAY_REQUEST_REJECTED"
    return JSONResponse(
        status_code=status_code,
        content={
            "contract": GATEWAY_CONTRACT,
            "accepted": False,
            "reason_codes": [reason_code],
        },
        headers=_security_headers(),
    )


def _validate_upstream(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise GatewayConfigError("INVALID_UPSTREAM_BASE_URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GatewayConfigError("INVALID_UPSTREAM_BASE_URL")
    return value.rstrip("/")


def _validate_config(config: GatewayConfig) -> GatewayConfig:
    upstream_base_url = _validate_upstream(config.upstream_base_url)
    if (
        not isinstance(config.upstream_id, str)
        or not config.upstream_id
        or config.upstream_id != config.upstream_id.strip()
        or "\x00" in config.upstream_id
    ):
        raise GatewayConfigError("INVALID_UPSTREAM_ID")
    for value, code in (
        (config.max_proof_bytes, "INVALID_MAX_PROOF_BYTES"),
        (config.max_proxy_body_bytes, "INVALID_MAX_PROXY_BODY_BYTES"),
        (config.max_upstream_response_bytes, "INVALID_MAX_UPSTREAM_RESPONSE_BYTES"),
    ):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 1 <= value <= MAX_CONFIGURED_BODY_BYTES
        ):
            raise GatewayConfigError(code)
    if (
        not isinstance(config.admission_ttl_seconds, int)
        or isinstance(config.admission_ttl_seconds, bool)
        or not 1 <= config.admission_ttl_seconds <= 300
    ):
        raise GatewayConfigError("INVALID_ADMISSION_TTL")
    if (
        not isinstance(config.upstream_timeout_seconds, (int, float))
        or isinstance(config.upstream_timeout_seconds, bool)
        or not 0 < float(config.upstream_timeout_seconds) <= 60
    ):
        raise GatewayConfigError("INVALID_UPSTREAM_TIMEOUT")
    if not isinstance(config.forward_headers, tuple):
        raise GatewayConfigError("INVALID_FORWARD_HEADERS")
    normalized: list[str] = []
    for name in config.forward_headers:
        try:
            canonical = canonical_gateway_headers({name: ""})
        except GatewayTargetError as exc:
            raise GatewayConfigError("INVALID_FORWARD_HEADER") from exc
        normalized.extend(canonical)
    if len(set(normalized)) != len(normalized):
        raise GatewayConfigError("DUPLICATE_FORWARD_HEADER")
    return GatewayConfig(
        upstream_base_url=upstream_base_url,
        upstream_id=config.upstream_id,
        max_proof_bytes=config.max_proof_bytes,
        max_proxy_body_bytes=config.max_proxy_body_bytes,
        max_upstream_response_bytes=config.max_upstream_response_bytes,
        admission_ttl_seconds=config.admission_ttl_seconds,
        upstream_timeout_seconds=float(config.upstream_timeout_seconds),
        forward_headers=tuple(sorted(normalized)),
    )


def _content_length(request: Request) -> int | None:
    values = request.headers.getlist("content-length")
    if not values:
        return None
    if len(values) != 1 or not values[0].isdecimal():
        raise GatewayRequestError(400, "INVALID_CONTENT_LENGTH")
    try:
        value = int(values[0])
    except (ValueError, OverflowError) as exc:
        raise GatewayRequestError(400, "INVALID_CONTENT_LENGTH") from exc
    return value


async def _read_bounded_body(request: Request, limit: int) -> bytes:
    declared = _content_length(request)
    if declared is not None and declared > limit:
        raise GatewayRequestError(413, "REQUEST_BODY_TOO_LARGE")
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > limit:
                raise GatewayRequestError(413, "REQUEST_BODY_TOO_LARGE")
            body.extend(chunk)
    except GatewayRequestError:
        raise
    except Exception as exc:
        raise GatewayRequestError(400, "REQUEST_BODY_READ_FAILED") from exc
    if declared is not None and len(body) != declared:
        raise GatewayRequestError(400, "CONTENT_LENGTH_MISMATCH")
    return bytes(body)


def _require_identity_encoding(request: Request) -> None:
    value = request.headers.get("content-encoding")
    if value is not None and value.strip().lower() not in {"", "identity"}:
        raise GatewayRequestError(415, "UNSUPPORTED_CONTENT_ENCODING")


def _proof_expiry(proof: dict[str, Any], now: datetime, ttl_seconds: int) -> str:
    evidence = proof.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise GatewayRequestError(403, "GATEWAY_EVIDENCE_EXPIRY_REQUIRED")
    expiries: list[tuple[tuple[int, str], str]] = []
    for item in evidence:
        if not isinstance(item, dict):
            raise GatewayRequestError(403, "GATEWAY_EVIDENCE_EXPIRY_REQUIRED")
        raw_expiry = item.get("expires_at")
        if not isinstance(raw_expiry, str) or not raw_expiry:
            raise GatewayRequestError(403, "GATEWAY_EVIDENCE_EXPIRY_REQUIRED")
        try:
            expiries.append((parse_rfc3339(raw_expiry), raw_expiry))
        except (TypeError, ValueError) as exc:
            raise GatewayRequestError(403, "INVALID_GATEWAY_EVIDENCE_EXPIRY") from exc

    now_value = timestamp_from_datetime(now)
    earliest_parsed, earliest_raw = min(expiries, key=lambda item: item[0])
    ttl_raw = (now + timedelta(seconds=ttl_seconds)).isoformat(timespec="milliseconds")
    ttl_parsed = parse_rfc3339(ttl_raw)
    chosen_parsed, chosen_raw = (
        (earliest_parsed, earliest_raw)
        if compare_timestamps(earliest_parsed, ttl_parsed) <= 0
        else (ttl_parsed, ttl_raw)
    )
    if compare_timestamps(chosen_parsed, now_value) <= 0:
        raise GatewayRequestError(403, "GATEWAY_ADMISSION_ALREADY_EXPIRED")
    return chosen_raw


def _admission_record(proof: dict[str, Any], *, now: datetime, ttl_seconds: int) -> GatewayAdmissionRecord:
    if proof.get("schema") != "operationproof.operation-proof.v2":
        raise GatewayRequestError(403, "GATEWAY_REQUIRES_PROOF_V2")
    if proof.get("phase") != "PRE":
        raise GatewayRequestError(403, "GATEWAY_REQUIRES_PRE_PROOF")
    operation_id = proof.get("operation_id")
    proof_digest = proof.get("proof_digest")
    subject_digest = proof.get("subject_digest")
    subject = proof.get("subject")
    if not isinstance(operation_id, str) or not operation_id:
        raise GatewayRequestError(403, "INVALID_GATEWAY_OPERATION_ID")
    if not isinstance(proof_digest, str) or not valid_digest(proof_digest):
        raise GatewayRequestError(403, "INVALID_GATEWAY_PROOF_DIGEST")
    if not isinstance(subject_digest, str) or not valid_digest(subject_digest):
        raise GatewayRequestError(403, "INVALID_GATEWAY_SUBJECT_DIGEST")
    if not isinstance(subject, dict):
        raise GatewayRequestError(403, "INVALID_GATEWAY_SUBJECT")
    target_digest = subject.get("target_digest")
    if not isinstance(target_digest, str) or not valid_digest(target_digest):
        raise GatewayRequestError(403, "INVALID_GATEWAY_TARGET_DIGEST")
    expires_at = _proof_expiry(proof, now, ttl_seconds)
    return GatewayAdmissionRecord(
        operation_id=operation_id,
        proof_digest=proof_digest,
        subject_digest=subject_digest,
        target_digest=target_digest,
        issued_at=now.isoformat(timespec="milliseconds"),
        expires_at=expires_at,
    )


def _extract_admission_token(request: Request) -> str:
    values = request.headers.getlist(_ADMISSION_HEADER)
    if len(values) != 1:
        raise GatewayRequestError(401, "ADMISSION_TOKEN_REQUIRED")
    token = values[0]
    if not token or token != token.strip() or "\x00" in token or len(token) > 512:
        raise GatewayRequestError(401, "INVALID_ADMISSION_TOKEN")
    return token


def _extract_forward_headers(request: Request, allowed: tuple[str, ...]) -> dict[str, str]:
    for name, _value in request.scope.get("headers", []):
        try:
            decoded_name = name.decode("ascii").lower()
        except (UnicodeDecodeError, AttributeError) as exc:
            raise GatewayRequestError(400, "INVALID_REQUEST_HEADER") from exc
        if decoded_name.startswith(_INTERNAL_PREFIX) and decoded_name != _ADMISSION_HEADER:
            raise GatewayRequestError(400, "RESERVED_OPERATIONPROOF_HEADER")

    selected: dict[str, str] = {}
    for name in allowed:
        values = request.headers.getlist(name)
        if len(values) > 1:
            raise GatewayRequestError(400, "DUPLICATE_FORWARDED_HEADER")
        if values:
            selected[name] = values[0]
    try:
        return canonical_gateway_headers(selected)
    except GatewayTargetError as exc:
        raise GatewayRequestError(400, str(exc)) from exc


def _raw_query(request: Request) -> str:
    raw = request.scope.get("query_string", b"")
    if not isinstance(raw, bytes):
        raise GatewayRequestError(400, "INVALID_GATEWAY_QUERY")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GatewayRequestError(400, "INVALID_GATEWAY_QUERY") from exc


def _record_is_expired(record: GatewayAdmissionRecord, now: datetime) -> bool:
    try:
        return compare_timestamps(
            parse_rfc3339(record.expires_at),
            timestamp_from_datetime(now),
        ) <= 0
    except (TypeError, ValueError):
        return True


async def _read_upstream_response(response: httpx.Response, limit: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > limit:
            raise GatewayRequestError(502, "UPSTREAM_RESPONSE_TOO_LARGE")
        body.extend(chunk)
    return bytes(body)


def create_gateway_app(
    registry: ProviderTrustRegistry,
    admission_store: GatewayAdmissionStore,
    *,
    upstream_base_url: str,
    upstream_id: str,
    max_proof_bytes: int = DEFAULT_MAX_PROOF_BYTES,
    max_proxy_body_bytes: int = DEFAULT_MAX_PROXY_BODY_BYTES,
    max_upstream_response_bytes: int = DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES,
    admission_ttl_seconds: int = 30,
    upstream_timeout_seconds: float = 10.0,
    forward_headers: tuple[str, ...] = ("content-type",),
    clock: Callable[[], datetime] | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Create an active OperationProof gateway with one-time proof admission.

    Unlike integrity-only sidecar mode, gateway mode always requires trusted provider
    verification and an atomic admission store. The upstream is fixed out-of-band and
    cannot be selected by an HTTP request.
    """

    if not isinstance(registry, ProviderTrustRegistry):
        raise GatewayConfigError("TRUST_REGISTRY_REQUIRED")
    if not isinstance(admission_store, GatewayAdmissionStore):
        raise GatewayConfigError("ADMISSION_STORE_REQUIRED")
    config = _validate_config(
        GatewayConfig(
            upstream_base_url=upstream_base_url,
            upstream_id=upstream_id,
            max_proof_bytes=max_proof_bytes,
            max_proxy_body_bytes=max_proxy_body_bytes,
            max_upstream_response_bytes=max_upstream_response_bytes,
            admission_ttl_seconds=admission_ttl_seconds,
            upstream_timeout_seconds=upstream_timeout_seconds,
            forward_headers=forward_headers,
        )
    )
    clock_fn = clock or (lambda: datetime.now(UTC))
    owns_client = http_client is None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = http_client or httpx.AsyncClient(
            timeout=config.upstream_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        )
        app.state.gateway_client = client
        try:
            yield
        finally:
            if owns_client:
                await client.aclose()

    app = FastAPI(
        title="OperationProof Gateway",
        version="v1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_request: Request, _exc: Exception) -> JSONResponse:
        return _error_response(500, "INTERNAL_GATEWAY_ERROR")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse(
            status_code=200,
            content={"contract": GATEWAY_CONTRACT, "status": "alive"},
            headers=_security_headers(),
        )

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        return JSONResponse(
            status_code=200,
            content={
                "contract": GATEWAY_CONTRACT,
                "ready": True,
                "mode": "trusted-gateway",
                "upstream_id": config.upstream_id,
            },
            headers=_security_headers(),
        )

    @app.post("/v1/admissions")
    async def create_admission(request: Request) -> JSONResponse:
        media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            return _error_response(415, "UNSUPPORTED_MEDIA_TYPE")
        try:
            _require_identity_encoding(request)
            raw = await _read_bounded_body(request, config.max_proof_bytes)
        except GatewayRequestError as exc:
            return _error_response(exc.status_code, exc.reason_code)
        if not raw:
            return _error_response(400, "EMPTY_REQUEST_BODY")
        try:
            proof = parse_proof_json(raw)
        except ProofDocumentError as exc:
            return _error_response(400, str(exc))
        assessment = await run_in_threadpool(assess_proof, proof, registry=registry)
        if not assessment.accepted:
            return JSONResponse(
                status_code=403,
                content={
                    "contract": GATEWAY_CONTRACT,
                    "accepted": False,
                    "assessment": assessment.to_dict(),
                },
                headers=_security_headers(),
            )
        try:
            now = clock_fn().astimezone(UTC)
            record = _admission_record(
                proof,
                now=now,
                ttl_seconds=config.admission_ttl_seconds,
            )
            token = await run_in_threadpool(admission_store.reserve, record)
        except GatewayRequestError as exc:
            return _error_response(exc.status_code, exc.reason_code)
        except GatewayAdmissionStoreError as exc:
            code = str(exc)
            status = 409 if code == "PROOF_REPLAY_DETECTED" else 503
            return _error_response(status, code)
        return JSONResponse(
            status_code=201,
            content={
                "contract": GATEWAY_CONTRACT,
                "accepted": True,
                "admission_token": token,
                "operation_id": record.operation_id,
                "expires_at": record.expires_at,
            },
            headers=_security_headers(),
        )

    @app.api_route(
        "/v1/proxy/{proxy_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    )
    async def proxy(request: Request, proxy_path: str) -> Response:
        try:
            token = _extract_admission_token(request)
            record = await run_in_threadpool(admission_store.consume, token)
            if record is None:
                raise GatewayRequestError(401, "ADMISSION_TOKEN_INVALID_OR_CONSUMED")
            now = clock_fn().astimezone(UTC)
            if _record_is_expired(record, now):
                raise GatewayRequestError(401, "ADMISSION_TOKEN_EXPIRED")
            _require_identity_encoding(request)
            body = await _read_bounded_body(request, config.max_proxy_body_bytes)
            headers = _extract_forward_headers(request, config.forward_headers)
            path = "/" + proxy_path
            query = _raw_query(request)
            target = build_gateway_target(
                upstream_id=config.upstream_id,
                method=request.method,
                path=path,
                query=query,
                headers=headers,
                body=body,
            )
            if not hmac.compare_digest(target.digest, record.target_digest):
                raise GatewayRequestError(403, "GATEWAY_TARGET_DIGEST_MISMATCH")
        except GatewayRequestError as exc:
            return _error_response(exc.status_code, exc.reason_code)
        except GatewayTargetError as exc:
            return _error_response(400, str(exc))

        encoded_path = quote(path, safe="/%:@-._~!$&'()*+,;=")
        upstream_url = config.upstream_base_url + encoded_path
        if query:
            upstream_url += "?" + query
        upstream_headers = dict(headers)
        upstream_headers.update(
            {
                "x-operationproof-gateway-contract": GATEWAY_CONTRACT,
                "x-operationproof-operation-id": record.operation_id,
                "x-operationproof-proof-digest": record.proof_digest,
                "x-operationproof-subject-digest": record.subject_digest,
            }
        )
        client = request.app.state.gateway_client
        try:
            async with client.stream(
                request.method,
                upstream_url,
                headers=upstream_headers,
                content=body,
                follow_redirects=False,
            ) as upstream:
                upstream_body = await _read_upstream_response(
                    upstream,
                    config.max_upstream_response_bytes,
                )
                response_headers = _security_headers()
                content_type = upstream.headers.get("content-type")
                if content_type:
                    response_headers["content-type"] = content_type
                return Response(
                    status_code=upstream.status_code,
                    content=upstream_body,
                    headers=response_headers,
                )
        except GatewayRequestError as exc:
            return _error_response(exc.status_code, exc.reason_code)
        except httpx.HTTPError:
            return _error_response(502, "UPSTREAM_REQUEST_FAILED")

    return app
