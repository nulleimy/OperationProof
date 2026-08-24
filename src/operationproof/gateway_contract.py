from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from .canonical import sha256_digest, valid_digest

GATEWAY_TARGET_CONTRACT = "operationproof.gateway-target.v1"
_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+$")
_RESERVED_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


class GatewayTargetError(ValueError):
    """Raised when a request cannot be represented as one canonical gateway target."""


def _text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise GatewayTargetError(code)
    return value


def normalize_gateway_method(method: str) -> str:
    value = _text(method, "INVALID_GATEWAY_METHOD").upper()
    if value not in _ALLOWED_METHODS:
        raise GatewayTargetError("UNSUPPORTED_GATEWAY_METHOD")
    return value


def normalize_gateway_path(path: str) -> str:
    value = _text(path, "INVALID_GATEWAY_PATH")
    if not value.startswith("/") or "?" in value or "#" in value or "\\" in value:
        raise GatewayTargetError("INVALID_GATEWAY_PATH")
    try:
        decoded = unquote(value, errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise GatewayTargetError("INVALID_GATEWAY_PATH") from exc
    if "\x00" in decoded or "\\" in decoded:
        raise GatewayTargetError("INVALID_GATEWAY_PATH")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise GatewayTargetError("GATEWAY_PATH_TRAVERSAL_FORBIDDEN")
    return value


def normalize_gateway_query(query: str) -> str:
    if not isinstance(query, str) or "\x00" in query or "#" in query:
        raise GatewayTargetError("INVALID_GATEWAY_QUERY")
    try:
        query.encode("ascii")
    except UnicodeEncodeError as exc:
        raise GatewayTargetError("INVALID_GATEWAY_QUERY") from exc
    return query


def canonical_gateway_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, Mapping):
        raise GatewayTargetError("INVALID_GATEWAY_HEADERS")
    normalized: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise GatewayTargetError("INVALID_GATEWAY_HEADER")
        name = raw_name.lower()
        if (
            not name
            or _HEADER_NAME.fullmatch(name) is None
            or name in _RESERVED_HEADERS
            or name.startswith("x-operationproof-")
        ):
            raise GatewayTargetError("FORBIDDEN_GATEWAY_HEADER")
        if any(ord(char) < 32 and char != "\t" for char in raw_value) or "\x7f" in raw_value:
            raise GatewayTargetError("INVALID_GATEWAY_HEADER_VALUE")
        if name in normalized:
            raise GatewayTargetError("DUPLICATE_GATEWAY_HEADER")
        normalized[name] = raw_value
    return dict(sorted(normalized.items()))


def raw_body_digest(body: bytes | bytearray) -> str:
    if not isinstance(body, (bytes, bytearray)):
        raise GatewayTargetError("INVALID_GATEWAY_BODY")
    return "sha256:" + hashlib.sha256(bytes(body)).hexdigest()


@dataclass(frozen=True, slots=True)
class GatewayTarget:
    upstream_id: str
    method: str
    path: str
    query: str
    headers_digest: str
    body_digest: str
    contract: str = GATEWAY_TARGET_CONTRACT

    def __post_init__(self) -> None:
        _text(self.upstream_id, "INVALID_GATEWAY_UPSTREAM_ID")
        if self.upstream_id != self.upstream_id.strip():
            raise GatewayTargetError("INVALID_GATEWAY_UPSTREAM_ID")
        if self.contract != GATEWAY_TARGET_CONTRACT:
            raise GatewayTargetError("INVALID_GATEWAY_TARGET_CONTRACT")
        normalize_gateway_method(self.method)
        normalize_gateway_path(self.path)
        normalize_gateway_query(self.query)
        if not valid_digest(self.headers_digest):
            raise GatewayTargetError("INVALID_GATEWAY_HEADERS_DIGEST")
        if not valid_digest(self.body_digest):
            raise GatewayTargetError("INVALID_GATEWAY_BODY_DIGEST")

    def to_dict(self) -> dict[str, str]:
        return {
            "contract": self.contract,
            "upstream_id": self.upstream_id,
            "method": normalize_gateway_method(self.method),
            "path": normalize_gateway_path(self.path),
            "query": normalize_gateway_query(self.query),
            "headers_digest": self.headers_digest,
            "body_digest": self.body_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(self.to_dict())


def build_gateway_target(
    *,
    upstream_id: str,
    method: str,
    path: str,
    query: str = "",
    headers: Mapping[str, str] | None = None,
    body: bytes | bytearray = b"",
) -> GatewayTarget:
    normalized_headers = canonical_gateway_headers(headers)
    return GatewayTarget(
        upstream_id=_text(upstream_id, "INVALID_GATEWAY_UPSTREAM_ID"),
        method=normalize_gateway_method(method),
        path=normalize_gateway_path(path),
        query=normalize_gateway_query(query),
        headers_digest=sha256_digest({"headers": normalized_headers}),
        body_digest=raw_body_digest(body),
    )


def gateway_target_digest(**kwargs: Any) -> str:
    return build_gateway_target(**kwargs).digest
