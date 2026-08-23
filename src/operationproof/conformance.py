from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .canonical import canonical_json_bytes
from .domain import EvidenceEnvelope
from .provider import ProviderAdapterManifest, validate_adapter_output

CONFORMANCE_CONTRACT = "operationproof.provider-conformance.v1"


class ConformanceScenario(StrEnum):
    VALID = "VALID"
    OPERATION_MISMATCH = "OPERATION_MISMATCH"
    UNTRUSTED_AUTHORITY = "UNTRUSTED_AUTHORITY"
    AUTHORITY_ERROR = "AUTHORITY_ERROR"
    MUTATION_ISOLATION = "MUTATION_ISOLATION"
    DETERMINISM = "DETERMINISM"


_REQUIRED_SCENARIOS = frozenset(ConformanceScenario)
_SUCCESS_SCENARIOS = frozenset(
    {
        ConformanceScenario.VALID,
        ConformanceScenario.MUTATION_ISOLATION,
    }
)
_FAILURE_SCENARIOS = frozenset(
    {
        ConformanceScenario.OPERATION_MISMATCH,
        ConformanceScenario.UNTRUSTED_AUTHORITY,
        ConformanceScenario.AUTHORITY_ERROR,
    }
)


@dataclass(frozen=True, slots=True)
class ProviderConformanceCase:
    """One provider-owned executable case consumed by the generic conformance runner.

    The scenario determines whether success or fail-closed behavior is mandatory;
    adapter authors cannot weaken those expectations per case.
    """

    scenario: ConformanceScenario
    invoke: Callable[[], EvidenceEnvelope]
    expected_operation_id: str
    postcondition: Callable[[EvidenceEnvelope], bool] | None = None


@dataclass(frozen=True, slots=True)
class ProviderConformanceCaseResult:
    scenario: str
    passed: bool
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "passed": self.passed,
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class ProviderConformanceReport:
    contract: str
    adapter_id: str
    provider_id: str
    layer: str
    passed: bool
    reason_codes: tuple[str, ...]
    cases: tuple[ProviderConformanceCaseResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "adapter_id": self.adapter_id,
            "provider_id": self.provider_id,
            "layer": self.layer,
            "passed": self.passed,
            "reason_codes": list(self.reason_codes),
            "cases": [item.to_dict() for item in self.cases],
        }


class ProviderConformanceError(ValueError):
    """Raised when a conformance suite itself is malformed."""


def _validate_suite(cases: tuple[ProviderConformanceCase, ...]) -> None:
    if not isinstance(cases, tuple):
        raise ProviderConformanceError("CONFORMANCE_CASES_MUST_BE_TUPLE")
    seen: set[ConformanceScenario] = set()
    for case in cases:
        if not isinstance(case, ProviderConformanceCase):
            raise ProviderConformanceError("INVALID_CONFORMANCE_CASE")
        if not isinstance(case.scenario, ConformanceScenario):
            raise ProviderConformanceError("INVALID_CONFORMANCE_SCENARIO")
        if case.scenario in seen:
            raise ProviderConformanceError(f"DUPLICATE_CONFORMANCE_SCENARIO:{case.scenario.value}")
        seen.add(case.scenario)
        if not callable(case.invoke):
            raise ProviderConformanceError(f"INVALID_CONFORMANCE_INVOKE:{case.scenario.value}")
        if not isinstance(case.expected_operation_id, str) or not case.expected_operation_id:
            raise ProviderConformanceError(
                f"INVALID_CONFORMANCE_OPERATION_ID:{case.scenario.value}"
            )
        if case.postcondition is not None and not callable(case.postcondition):
            raise ProviderConformanceError(
                f"INVALID_CONFORMANCE_POSTCONDITION:{case.scenario.value}"
            )
    missing = _REQUIRED_SCENARIOS - seen
    extra = seen - _REQUIRED_SCENARIOS
    if missing:
        raise ProviderConformanceError(
            "MISSING_CONFORMANCE_SCENARIOS:" + ",".join(sorted(item.value for item in missing))
        )
    if extra:
        raise ProviderConformanceError(
            "UNEXPECTED_CONFORMANCE_SCENARIOS:" + ",".join(sorted(item.value for item in extra))
        )


def _run_success_case(
    manifest: ProviderAdapterManifest,
    case: ProviderConformanceCase,
    adapter_error: type[Exception],
) -> ProviderConformanceCaseResult:
    reasons: list[str] = []
    try:
        envelope = case.invoke()
    except adapter_error:
        reasons.append("VALID_CASE_RAISED_ADAPTER_ERROR")
        return ProviderConformanceCaseResult(case.scenario.value, False, tuple(reasons))
    except Exception as exc:  # noqa: BLE001 - report unexpected provider boundary failures
        reasons.append(f"UNEXPECTED_EXCEPTION:{type(exc).__name__}")
        return ProviderConformanceCaseResult(case.scenario.value, False, tuple(reasons))

    validation = validate_adapter_output(
        manifest,
        envelope,
        expected_operation_id=case.expected_operation_id,
    )
    reasons.extend(validation.reason_codes)
    if case.postcondition is not None:
        try:
            postcondition_ok = case.postcondition(envelope)
        except Exception as exc:  # noqa: BLE001 - conformance postcondition is provider-owned code
            reasons.append(f"POSTCONDITION_ERROR:{type(exc).__name__}")
        else:
            if postcondition_ok is not True:
                reasons.append("POSTCONDITION_FAILED")
    return ProviderConformanceCaseResult(
        scenario=case.scenario.value,
        passed=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
    )


def _run_failure_case(
    case: ProviderConformanceCase,
    adapter_error: type[Exception],
) -> ProviderConformanceCaseResult:
    reasons: list[str] = []
    try:
        case.invoke()
    except adapter_error:
        pass
    except Exception as exc:  # noqa: BLE001 - wrong exception type is itself a conformance failure
        reasons.append(f"UNEXPECTED_EXCEPTION:{type(exc).__name__}")
    else:
        reasons.append("FAIL_CLOSED_CASE_RETURNED_EVIDENCE")
    return ProviderConformanceCaseResult(
        scenario=case.scenario.value,
        passed=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
    )


def _run_determinism_case(
    manifest: ProviderAdapterManifest,
    case: ProviderConformanceCase,
    adapter_error: type[Exception],
) -> ProviderConformanceCaseResult:
    reasons: list[str] = []
    outputs: list[EvidenceEnvelope] = []
    for _ in range(2):
        try:
            envelope = case.invoke()
        except adapter_error:
            reasons.append("DETERMINISM_CASE_RAISED_ADAPTER_ERROR")
            break
        except Exception as exc:  # noqa: BLE001 - report unexpected provider boundary failures
            reasons.append(f"UNEXPECTED_EXCEPTION:{type(exc).__name__}")
            break
        validation = validate_adapter_output(
            manifest,
            envelope,
            expected_operation_id=case.expected_operation_id,
        )
        reasons.extend(validation.reason_codes)
        outputs.append(envelope)

    if len(outputs) == 2 and not reasons:
        try:
            first = canonical_json_bytes(outputs[0].to_dict())
            second = canonical_json_bytes(outputs[1].to_dict())
        except (TypeError, ValueError, OverflowError, RecursionError):
            reasons.append("DETERMINISM_OUTPUT_NOT_CANONICAL_JSON")
        else:
            if first != second:
                reasons.append("NON_DETERMINISTIC_ADAPTER_OUTPUT")

    if case.postcondition is not None and outputs:
        try:
            postcondition_ok = case.postcondition(outputs[-1])
        except Exception as exc:  # noqa: BLE001 - provider-owned conformance code
            reasons.append(f"POSTCONDITION_ERROR:{type(exc).__name__}")
        else:
            if postcondition_ok is not True:
                reasons.append("POSTCONDITION_FAILED")

    return ProviderConformanceCaseResult(
        scenario=case.scenario.value,
        passed=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
    )


def run_provider_conformance(
    manifest: ProviderAdapterManifest,
    *,
    adapter_error: type[Exception],
    cases: tuple[ProviderConformanceCase, ...],
) -> ProviderConformanceReport:
    """Execute the mandatory provider adapter conformance profile.

    PASS means the supplied adapter scenarios satisfy this generic harness. It does
    not make the provider authoritative at runtime; provider authenticity still flows
    through ``ProviderTrustRegistry`` and its external verifier callbacks.
    """

    if not isinstance(manifest, ProviderAdapterManifest):
        raise ProviderConformanceError("INVALID_PROVIDER_ADAPTER_MANIFEST")
    if not isinstance(adapter_error, type) or not issubclass(adapter_error, Exception):
        raise ProviderConformanceError("INVALID_ADAPTER_ERROR_TYPE")
    _validate_suite(cases)

    results: list[ProviderConformanceCaseResult] = []
    for scenario in ConformanceScenario:
        case = next(item for item in cases if item.scenario is scenario)
        if scenario in _SUCCESS_SCENARIOS:
            result = _run_success_case(manifest, case, adapter_error)
        elif scenario in _FAILURE_SCENARIOS:
            result = _run_failure_case(case, adapter_error)
        elif scenario is ConformanceScenario.DETERMINISM:
            result = _run_determinism_case(manifest, case, adapter_error)
        else:  # pragma: no cover - enum exhaustiveness guard
            raise ProviderConformanceError(f"UNHANDLED_CONFORMANCE_SCENARIO:{scenario.value}")
        results.append(result)

    report_reasons = tuple(
        sorted(
            f"{item.scenario}:{reason}"
            for item in results
            for reason in item.reason_codes
        )
    )
    return ProviderConformanceReport(
        contract=CONFORMANCE_CONTRACT,
        adapter_id=manifest.adapter_id,
        provider_id=manifest.provider_id,
        layer=manifest.layer.value,
        passed=all(item.passed for item in results),
        reason_codes=report_reasons,
        cases=tuple(results),
    )
