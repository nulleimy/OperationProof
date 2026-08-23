from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest

from operationproof.sidecar_runtime import TrustFactoryError, load_trust_registry, main
from operationproof.trust import ProviderTrustRegistry


def install_factory_module(monkeypatch: pytest.MonkeyPatch, result: object) -> str:
    module = ModuleType("operationproof_test_trust_factory")
    module.build_registry = lambda: result  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return f"{module.__name__}:build_registry"


def test_trust_factory_must_return_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = install_factory_module(monkeypatch, object())

    with pytest.raises(TrustFactoryError, match="TRUST_FACTORY_INVALID_RESULT"):
        load_trust_registry(spec)


def test_trust_factory_loads_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = ProviderTrustRegistry()
    spec = install_factory_module(monkeypatch, expected)

    assert load_trust_registry(spec) is expected


def test_runtime_refuses_implicit_integrity_only_mode() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])

    assert exc.value.code == 2


def test_runtime_integrity_only_mode_is_explicit_and_loopback_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, dict[str, object]]] = []

    def fake_run(app: object, **kwargs: object) -> None:
        calls.append((app, kwargs))

    monkeypatch.setitem(sys.modules, "uvicorn", SimpleNamespace(run=fake_run))

    assert main(["--allow-integrity-only"]) == 0
    assert len(calls) == 1
    _, kwargs = calls[0]
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 8080
    assert kwargs["proxy_headers"] is False
    assert kwargs["server_header"] is False
    assert kwargs["date_header"] is False
    assert kwargs["workers"] == 1


def test_runtime_uses_trusted_factory_without_integrity_only_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = install_factory_module(monkeypatch, ProviderTrustRegistry())
    calls: list[dict[str, object]] = []

    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(run=lambda app, **kwargs: calls.append(kwargs)),
    )

    assert main(["--trust-factory", spec, "--port", "8091"]) == 0
    assert calls[0]["port"] == 8091
