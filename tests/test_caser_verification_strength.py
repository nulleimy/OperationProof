import pytest

from operationproof.adapters.caser import CaserExecutionError, _validate_strength_contract


def verification(*, strength: str, scope: str) -> dict[str, object]:
    return {
        "verificationStrength": strength,
        "verificationScope": scope,
    }


def test_v2_integrity_only_contract_is_accepted() -> None:
    _validate_strength_contract(
        verification(strength="V2", scope="EXECUTION_EVIDENCE_INTEGRITY"),
        outcome_verified=False,
        post_state_verified=False,
    )


def test_v2_cannot_claim_verified_execution_outcome() -> None:
    with pytest.raises(CaserExecutionError, match="CASER_V2_CLAIM_ESCALATION"):
        _validate_strength_contract(
            verification(strength="V2", scope="EXECUTION_EVIDENCE_INTEGRITY"),
            outcome_verified=True,
            post_state_verified=False,
        )


def test_v2_cannot_claim_stronger_scope() -> None:
    with pytest.raises(
        CaserExecutionError,
        match="CASER_V2_OUTSIDE_INTEGRITY_ONLY_SCOPE",
    ):
        _validate_strength_contract(
            verification(strength="V2", scope="EXECUTION_OUTCOME"),
            outcome_verified=False,
            post_state_verified=False,
        )


def test_unknown_strength_fails_closed() -> None:
    with pytest.raises(
        CaserExecutionError,
        match="UNSUPPORTED_CASER_VERIFICATION_STRENGTH",
    ):
        _validate_strength_contract(
            verification(strength="V4", scope="EXECUTION_OUTCOME"),
            outcome_verified=True,
            post_state_verified=False,
        )


def test_v3_can_reach_existing_outcome_gates() -> None:
    _validate_strength_contract(
        verification(strength="V3", scope="EXECUTION_OUTCOME"),
        outcome_verified=True,
        post_state_verified=False,
    )
