from __future__ import annotations

import hashlib
import json
import re
from typing import Any

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def valid_digest(value: str) -> bool:
    return bool(DIGEST_RE.fullmatch(value))


def proof_payload(proof: dict[str, Any]) -> dict[str, Any]:
    payload = dict(proof)
    payload.pop("proof_digest", None)
    return payload
