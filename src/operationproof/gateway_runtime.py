from __future__ import annotations

import argparse
import importlib
from collections.abc import Callable, Sequence

from .gateway_store import (
    GatewayAdmissionStore,
    GatewayAdmissionStoreError,
    MemoryGatewayAdmissionStore,
)
from .sidecar_runtime import TrustFactoryError, load_trust_registry


class AdmissionStoreFactoryError(RuntimeError):
    """Raised when gateway runtime cannot construct its replay/admission boundary."""


def load_admission_store(factory_spec: str) -> GatewayAdmissionStore:
    module_name, separator, attribute_name = factory_spec.partition(":")
    if not separator or not module_name or not attribute_name:
        raise AdmissionStoreFactoryError("INVALID_ADMISSION_STORE_FACTORY_SPEC")
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise AdmissionStoreFactoryError("ADMISSION_STORE_FACTORY_IMPORT_FAILED") from exc
    factory = getattr(module, attribute_name, None)
    if not isinstance(factory, Callable):
        raise AdmissionStoreFactoryError("ADMISSION_STORE_FACTORY_NOT_CALLABLE")
    try:
        store = factory()
    except Exception as exc:
        raise AdmissionStoreFactoryError("ADMISSION_STORE_FACTORY_EXECUTION_FAILED") from exc
    if not isinstance(store, GatewayAdmissionStore):
        raise AdmissionStoreFactoryError("ADMISSION_STORE_FACTORY_INVALID_RESULT")
    return store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the OperationProof trusted gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--trust-factory", required=True)
    parser.add_argument("--admission-store-factory")
    parser.add_argument("--allow-ephemeral-admission-store", action="store_true")
    parser.add_argument("--ephemeral-store-capacity", type=int, default=10_000)
    parser.add_argument("--upstream-base-url", required=True)
    parser.add_argument("--upstream-id", required=True)
    parser.add_argument("--forward-header", action="append", default=["content-type"])
    parser.add_argument("--max-proof-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--max-proxy-body-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--max-upstream-response-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--admission-ttl-seconds", type=int, default=30)
    parser.add_argument("--upstream-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--limit-concurrency", type=int, default=100)
    parser.add_argument("--timeout-keep-alive", type=int, default=5)
    parser.add_argument(
        "--log-level",
        choices=("critical", "error", "warning", "info"),
        default="info",
    )
    return parser


def _positive_port(value: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _positive(value: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not _positive_port(args.port):
        parser.error("--port must be between 1 and 65535")
    if not _positive(args.limit_concurrency):
        parser.error("--limit-concurrency must be positive")
    if not _positive(args.timeout_keep_alive):
        parser.error("--timeout-keep-alive must be positive")
    if not _positive(args.ephemeral_store_capacity):
        parser.error("--ephemeral-store-capacity must be positive")

    try:
        registry = load_trust_registry(args.trust_factory)
    except TrustFactoryError as exc:
        parser.error(str(exc))

    if args.admission_store_factory and args.allow_ephemeral_admission_store:
        parser.error(
            "choose --admission-store-factory or --allow-ephemeral-admission-store, not both"
        )
    if args.admission_store_factory:
        try:
            admission_store = load_admission_store(args.admission_store_factory)
        except AdmissionStoreFactoryError as exc:
            parser.error(str(exc))
    elif args.allow_ephemeral_admission_store:
        try:
            admission_store = MemoryGatewayAdmissionStore(
                max_records=args.ephemeral_store_capacity
            )
        except GatewayAdmissionStoreError as exc:
            parser.error(str(exc))
    else:
        parser.error(
            "--admission-store-factory is required unless "
            "--allow-ephemeral-admission-store is explicitly set"
        )

    try:
        import uvicorn

        from .gateway import GatewayConfigError, create_gateway_app
    except ModuleNotFoundError as exc:
        parser.error("gateway dependencies are missing; install operationproof[gateway]")
        raise AssertionError("unreachable") from exc

    try:
        app = create_gateway_app(
            registry,
            admission_store,
            upstream_base_url=args.upstream_base_url,
            upstream_id=args.upstream_id,
            max_proof_bytes=args.max_proof_bytes,
            max_proxy_body_bytes=args.max_proxy_body_bytes,
            max_upstream_response_bytes=args.max_upstream_response_bytes,
            admission_ttl_seconds=args.admission_ttl_seconds,
            upstream_timeout_seconds=args.upstream_timeout_seconds,
            forward_headers=tuple(args.forward_header),
        )
    except GatewayConfigError as exc:
        parser.error(str(exc))

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        proxy_headers=False,
        server_header=False,
        date_header=False,
        limit_concurrency=args.limit_concurrency,
        timeout_keep_alive=args.timeout_keep_alive,
        workers=1,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
