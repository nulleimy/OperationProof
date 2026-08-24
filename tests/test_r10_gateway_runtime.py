from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest

from operationproof.gateway_runtime import (
    AdmissionStoreFactoryError,
    load_admission_store,
    main,
)
from operationproof.gateway_store import MemoryGatewayAdmissionStore
from operationproof.trust import ProviderTrustRegistry


def _install_module(
    monkeypatch: pytest.MonkeyPatch,
    *,
    registry: object = None,
    store: object = None,
) -> tuple[str, str]:
    module = ModuleType("operationproof_test_gateway_factories")
    module.build_registry = lambda: registry  # type: ignore[attr-defined]
    module.build_store = lambda: store  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return f"{module.__name__}:build_registry", f"{module.__name__}:build_store"


def _base_args(trust_spec: str) -> list[str]:
    return [
        "--trust-factory",
        trust_spec,
        "--upstream-base-url",
        "https://upstream.test",
        "--upstream-id",
        "service-a",
    ]


def test_admission_store_factory_must_return_store(monkeypatch: pytest.MonkeyPatch) -> None:
    _trust, store_spec = _install_module(monkeypatch, store=object())

    with pytest.raises(AdmissionStoreFactoryError, match="ADMISSION_STORE_FACTORY_INVALID_RESULT"):
        load_admission_store(store_spec)


def test_admission_store_factory_loads_store(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = MemoryGatewayAdmissionStore()
    _trust, store_spec = _install_module(monkeypatch, store=expected)

    assert load_admission_store(store_spec) is expected


def test_gateway_runtime_refuses_missing_replay_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trust_spec, _store = _install_module(
        monkeypatch,
        registry=ProviderTrustRegistry(),
    )

    with pytest.raises(SystemExit) as exc:
        main(_base_args(trust_spec))

    assert exc.value.code == 2


def test_ephemeral_store_requires_explicit_flag_and_keeps_hardened_uvicorn_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trust_spec, _store = _install_module(
        monkeypatch,
        registry=ProviderTrustRegistry(),
    )
    calls: list[dict[str, object]] = []
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(run=lambda app, **kwargs: calls.append(kwargs)),
    )

    assert main(_base_args(trust_spec) + ["--allow-ephemeral-admission-store"]) == 0
    assert len(calls) == 1
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 8081
    assert calls[0]["proxy_headers"] is False
    assert calls[0]["server_header"] is False
    assert calls[0]["date_header"] is False
    assert calls[0]["workers"] == 1


def test_runtime_accepts_out_of_band_trust_and_admission_store_factories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trust_spec, store_spec = _install_module(
        monkeypatch,
        registry=ProviderTrustRegistry(),
        store=MemoryGatewayAdmissionStore(),
    )
    calls: list[dict[str, object]] = []
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(run=lambda app, **kwargs: calls.append(kwargs)),
    )

    args = _base_args(trust_spec) + ["--admission-store-factory", store_spec, "--port", "8092"]
    assert main(args) == 0
    assert calls[0]["port"] == 8092
