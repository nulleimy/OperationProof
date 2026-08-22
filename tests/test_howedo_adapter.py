import pytest

from operationproof.adapters.howedo import HowedoWitnessAdapter, HowedoWitnessError
from operationproof.builder import build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.verifier import verify_proof


def howedo_witness(action: str = "CONTINUE") -> dict[str, object]:
    snapshot_id = sha256_digest({"snapshot": "s1"})
    reason_codes = ("STATE_UNCHANGED",)
    witness_digest = sha256_digest(
        {
            "action": action,
            "reason_codes": reason_codes,
            "snapshot_id": snapshot_id,
        }
    )
    return {
        "snapshot_id": snapshot_id,
        "action": action,
        "reason_codes": list(reason_codes),
        "witness_digest": witness_digest,
    }


def generic_evidence(layer: Layer) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"test:{layer.value}",
        operation_id="op-1",
        decision="native-ok",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": layer.value}),
        evidence_digest=sha256_digest({"evidence": layer.value}),
        issued_at="2026-08-22T00:00:00+00:00",
    )


def test_continue_maps_to_passing_continuity_evidence() -> None:
    item = HowedoWitnessAdapter.adapt(
        operation_id="op-1",
        witness=howedo_witness(),
        issued_at="2026-08-22T00:00:00+00:00",
    )
    assert item.layer is Layer.CONTINUITY
    assert item.provider == "howedo"
    assert item.decision == "CONTINUE"
    assert item.verdict is Verdict.PASS
    assert item.evidence_digest == howedo_witness()["witness_digest"]


@pytest.mark.parametrize("action", ["PAUSE", "REVALIDATE", "ABORT", "RECOVER"])
def test_non_continue_actions_fail_closed(action: str) -> None:
    item = HowedoWitnessAdapter.adapt(
        operation_id="op-1",
        witness=howedo_witness(action),
        issued_at="2026-08-22T00:00:00+00:00",
    )
    assert item.verdict is Verdict.FAIL
    assert item.decision == action


def test_tampered_howedo_witness_is_rejected() -> None:
    witness = howedo_witness()
    witness["action"] = "ABORT"
    with pytest.raises(HowedoWitnessError, match="HOWEDO_WITNESS_DIGEST_MISMATCH"):
        HowedoWitnessAdapter.adapt(
            operation_id="op-1",
            witness=witness,
            issued_at="2026-08-22T00:00:00+00:00",
        )


def test_unknown_howedo_action_is_rejected() -> None:
    witness = howedo_witness()
    witness["action"] = "MAYBE"
    with pytest.raises(HowedoWitnessError, match="INVALID_HOWEDO_ACTION"):
        HowedoWitnessAdapter.adapt(
            operation_id="op-1",
            witness=witness,
            issued_at="2026-08-22T00:00:00+00:00",
        )


def test_howedo_evidence_composes_into_verified_pre_proof() -> None:
    continuity = HowedoWitnessAdapter.adapt(
        operation_id="op-1",
        witness=howedo_witness(),
        issued_at="2026-08-22T00:00:00+00:00",
    )
    evidence = [
        continuity if layer is Layer.CONTINUITY else generic_evidence(layer)
        for layer in PRE_LAYERS
    ]
    proof = build_pre_proof("op-1", evidence)
    assert proof["decision"] == "VERIFIED"
    assert verify_proof(proof).valid is True


def test_revalidate_witness_rejects_pre_proof() -> None:
    continuity = HowedoWitnessAdapter.adapt(
        operation_id="op-1",
        witness=howedo_witness("REVALIDATE"),
        issued_at="2026-08-22T00:00:00+00:00",
    )
    evidence = [
        continuity if layer is Layer.CONTINUITY else generic_evidence(layer)
        for layer in PRE_LAYERS
    ]
    proof = build_pre_proof("op-1", evidence)
    assert proof["decision"] == "REJECTED"
    assert "LAYER_FAIL:continuity" in proof["reason_codes"]
    assert verify_proof(proof).valid is True
