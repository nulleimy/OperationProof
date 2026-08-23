from __future__ import annotations

import argparse
import importlib
from collections.abc import Callable, Sequence

from .trust import ProviderTrustRegistry


class TrustFactoryError(RuntimeError):
    """Raised when trusted runtime bootstrap cannot construct a provider registry."""


def load_trust_registry(factory_spec: str) -> ProviderTrustRegistry:
    """Load a zero-argument trusted registry factory from ``module:attribute``."""

    module_name, separator, attribute_name = factory_spec.partition(":")
    if not separator or not module_name or not attribute_name:
        raise TrustFactoryError("INVALID_TRUST_FACTORY_SPEC")

    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - deployment bootstrap must fail closed
        raise TrustFactoryError("TRUST_FACTORY_IMPORT_FAILED") from exc

    factory = getattr(module, attribute_name, None)
    if not isinstance(factory, Callable):
        raise TrustFactoryError("TRUST_FACTORY_NOT_CALLABLE")

    try:
        registry = factory()
    except Exception as exc:  # noqa: BLE001 - deployment bootstrap must fail closed
        raise TrustFactoryError("TRUST_FACTORY_EXECUTION_FAILED") from exc
    if not isinstance(registry, ProviderTrustRegistry):
        raise TrustFactoryError("TRUST_FACTORY_INVALID_RESULT")
    return registry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the OperationProof sidecar runtime")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--trust-factory")
    parser.add_argument("--allow-integrity-only", action="store_true")
    parser.add_argument("--max-body-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--limit-concurrency", type=int, default=100)
    parser.add_argument("--timeout-keep-alive", type=int, default=5)
    parser.add_argument(
        "--log-level",
        choices=("critical", "error", "warning", "info"),
        default="info",
    )
    return parser


def _positive_port(value: int) -> bool:
    return 1 <= value <= 65535


def _positive_runtime_limit(value: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not _positive_port(args.port):
        parser.error("--port must be between 1 and 65535")
    if not _positive_runtime_limit(args.limit_concurrency):
        parser.error("--limit-concurrency must be positive")
    if not _positive_runtime_limit(args.timeout_keep_alive):
        parser.error("--timeout-keep-alive must be positive")

    registry: ProviderTrustRegistry | None = None
    if args.trust_factory:
        try:
            registry = load_trust_registry(args.trust_factory)
        except TrustFactoryError as exc:
            parser.error(str(exc))
    elif not args.allow_integrity_only:
        parser.error(
            "--trust-factory is required unless --allow-integrity-only is explicitly set"
        )

    try:
        import uvicorn
        from .sidecar import SidecarConfigError, create_app
    except ModuleNotFoundError as exc:
        parser.error(
            "sidecar dependencies are missing; install operationproof[sidecar]"
        )
        raise AssertionError("unreachable") from exc

    try:
        app = create_app(
            registry,
            require_trust=not args.allow_integrity_only,
            max_body_bytes=args.max_body_bytes,
        )
    except SidecarConfigError as exc:
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
