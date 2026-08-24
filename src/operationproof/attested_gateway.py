from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from typing import Any

import httpx

from .canonical import sha256_digest, valid_digest
from .gateway import create_gateway_app
from .gateway_store import GatewayAdmissionRecord, GatewayAdmissionStore, GatewayAdmissionStoreError
from .provenance import ProvenanceRecorder, ProvenanceRecorderError

PROVENANCE_POLICY_REQUIRED = "required"
TELEMETRY_POLICY_BEST_EFFORT = "best-effort"


class AttestedGatewayAdmissionStore(GatewayAdmissionStore):
    """R11 composition wrapper preserving the R10 admission/replay authority boundary."""

    def __init__(
        self,
        store: GatewayAdmissionStore,
        recorder: ProvenanceRecorder,
    ) -> None:
        if not isinstance(store, GatewayAdmissionStore):
            raise GatewayAdmissionStoreError("ADMISSION_STORE_REQUIRED")
        if not isinstance(recorder, ProvenanceRecorder):
            raise GatewayAdmissionStoreError("PROVENANCE_RECORDER_REQUIRED")
        self._store = store
        self._recorder = recorder

    def reserve(self, record: GatewayAdmissionRecord) -> str:
        if not isinstance(record, GatewayAdmissionRecord):
            raise GatewayAdmissionStoreError("INVALID_ADMISSION_RECORD")
        try:
            self._recorder.record_event(
                event_type="proof_assessed",
                operation_id=record.operation_id,
                subject_digest=record.subject_digest,
                proof_digest=record.proof_digest,
                artifact_digest=record.proof_digest,
                state_from="PRE_PROOF_RECEIVED",
                state_to="TRUSTED_PRE_ASSESSED",
                reason_codes=("R10_GATEWAY_ACCEPTED_PRE",),
            )
        except ProvenanceRecorderError as exc:
            raise GatewayAdmissionStoreError("PROVENANCE_PERSISTENCE_FAILED") from exc

        token = self._store.reserve(record)
        if (
            not isinstance(token, str)
            or not token
            or token != token.strip()
            or "\x00" in token
            or len(token) > 512
        ):
            raise GatewayAdmissionStoreError("INVALID_ADMISSION_TOKEN_FROM_STORE")
        try:
            self._recorder.record_event(
                event_type="admission_created",
                operation_id=record.operation_id,
                subject_digest=record.subject_digest,
                proof_digest=record.proof_digest,
                artifact_digest=record.target_digest,
                state_from="TRUSTED_PRE_ASSESSED",
                state_to="ADMISSION_CREATED",
            )
        except ProvenanceRecorderError as exc:
            # The underlying R10 capability remains reserved but is not returned to the client.
            raise GatewayAdmissionStoreError("PROVENANCE_PERSISTENCE_FAILED") from exc
        return token

    def consume(self, token: str) -> GatewayAdmissionRecord | None:
        record = self._store.consume(token)
        if record is None:
            return None
        if not isinstance(record, GatewayAdmissionRecord):
            raise GatewayAdmissionStoreError("INVALID_ADMISSION_RECORD_FROM_STORE")
        try:
            self._recorder.record_event(
                event_type="admission_consumed",
                operation_id=record.operation_id,
                subject_digest=record.subject_digest,
                proof_digest=record.proof_digest,
                artifact_digest=record.target_digest,
                state_from="ADMISSION_CREATED",
                state_to="ADMISSION_CONSUMED",
            )
        except ProvenanceRecorderError as exc:
            # Consumption is intentionally not rolled back: the one-time token stays burned.
            raise GatewayAdmissionStoreError("PROVENANCE_PERSISTENCE_FAILED") from exc
        return record


def _request_binding(
    method: object,
    url: object,
    headers: object,
    content: object,
) -> tuple[str, str, str, str]:
    if not isinstance(headers, dict):
        try:
            headers = dict(headers)
        except Exception as exc:
            raise ProvenanceRecorderError("INVALID_ATTESTED_UPSTREAM_HEADERS") from exc
    operation_id = headers.get("x-operationproof-operation-id")
    proof_digest = headers.get("x-operationproof-proof-digest")
    subject_digest = headers.get("x-operationproof-subject-digest")
    if not isinstance(operation_id, str) or not operation_id:
        raise ProvenanceRecorderError("MISSING_ATTESTED_OPERATION_ID")
    if not isinstance(proof_digest, str) or not valid_digest(proof_digest):
        raise ProvenanceRecorderError("MISSING_ATTESTED_PROOF_DIGEST")
    if not isinstance(subject_digest, str) or not valid_digest(subject_digest):
        raise ProvenanceRecorderError("MISSING_ATTESTED_SUBJECT_DIGEST")
    if not isinstance(method, str) or not method:
        raise ProvenanceRecorderError("INVALID_ATTESTED_UPSTREAM_METHOD")
    if not isinstance(content, (bytes, bytearray)):
        raise ProvenanceRecorderError("INVALID_ATTESTED_UPSTREAM_BODY")
    raw_body_digest = "sha256:" + hashlib.sha256(bytes(content)).hexdigest()
    artifact_digest = sha256_digest(
        {
            "method": method.upper(),
            "url": str(url),
            "body_digest": raw_body_digest,
        }
    )
    return operation_id, subject_digest, proof_digest, artifact_digest


class AttestedHTTPClient:
    """Startup-injected HTTP client decorator emitting required dispatch provenance."""

    def __init__(self, client: httpx.AsyncClient, recorder: ProvenanceRecorder) -> None:
        if not isinstance(client, httpx.AsyncClient):
            raise TypeError("HTTPX_ASYNC_CLIENT_REQUIRED")
        if not isinstance(recorder, ProvenanceRecorder):
            raise TypeError("PROVENANCE_RECORDER_REQUIRED")
        self._client = client
        self._recorder = recorder

    @asynccontextmanager
    async def stream(self, method: str, url: str, **kwargs: Any):
        operation_id, subject_digest, proof_digest, request_digest = _request_binding(
            method,
            url,
            kwargs.get("headers", {}),
            kwargs.get("content", b""),
        )
        self._recorder.record_event(
            event_type="upstream_dispatched",
            operation_id=operation_id,
            subject_digest=subject_digest,
            proof_digest=proof_digest,
            artifact_digest=request_digest,
            state_from="ADMISSION_CONSUMED",
            state_to="UPSTREAM_DISPATCHED",
        )
        failure_recorded = False
        try:
            async with self._client.stream(method, url, **kwargs) as response:
                try:
                    yield response
                except Exception:
                    failure_digest = sha256_digest(
                        {"request_digest": request_digest, "failure": "response_processing"}
                    )
                    self._recorder.record_event(
                        event_type="upstream_failed",
                        operation_id=operation_id,
                        subject_digest=subject_digest,
                        proof_digest=proof_digest,
                        artifact_digest=failure_digest,
                        state_from="UPSTREAM_DISPATCHED",
                        state_to="UPSTREAM_FAILED",
                        reason_codes=("UPSTREAM_RESPONSE_PROCESSING_FAILED",),
                    )
                    failure_recorded = True
                    raise
                completion_digest = sha256_digest(
                    {
                        "request_digest": request_digest,
                        "status_code": response.status_code,
                    }
                )
                self._recorder.record_event(
                    event_type="upstream_completed",
                    operation_id=operation_id,
                    subject_digest=subject_digest,
                    proof_digest=proof_digest,
                    artifact_digest=completion_digest,
                    state_from="UPSTREAM_DISPATCHED",
                    state_to="UPSTREAM_COMPLETED",
                )
        except ProvenanceRecorderError:
            raise
        except Exception:
            if not failure_recorded:
                failure_digest = sha256_digest(
                    {"request_digest": request_digest, "failure": "upstream_transport"}
                )
                self._recorder.record_event(
                    event_type="upstream_failed",
                    operation_id=operation_id,
                    subject_digest=subject_digest,
                    proof_digest=proof_digest,
                    artifact_digest=failure_digest,
                    state_from="UPSTREAM_DISPATCHED",
                    state_to="UPSTREAM_FAILED",
                    reason_codes=("UPSTREAM_TRANSPORT_FAILED",),
                )
            raise


def create_attested_gateway_app(
    registry: object,
    admission_store: GatewayAdmissionStore,
    provenance_recorder: ProvenanceRecorder,
    *,
    http_client: httpx.AsyncClient,
    **gateway_kwargs: Any,
):
    """Compose R11 required provenance around the unchanged R10 gateway authority path.

    Signer, verifier, attestation store, telemetry sink, admission store and upstream
    client are all startup/out-of-band dependencies. No HTTP request can select them.
    """

    if "http_client" in gateway_kwargs:
        raise TypeError("HTTP_CLIENT_MUST_BE_STARTUP_ARGUMENT")
    attested_store = AttestedGatewayAdmissionStore(admission_store, provenance_recorder)
    attested_client = AttestedHTTPClient(http_client, provenance_recorder)
    return create_gateway_app(
        registry,
        attested_store,
        http_client=attested_client,
        **gateway_kwargs,
    )
