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


def trusted_binding(
    witness: dict[str, object],
    *,
    operation_id: str = "op-1",
    issued_at: str = "2026-08-22T00:00:00+00:00",
    expires_at: str = "2030-01-01T00:00:00+00:00",
) -> dict[str, object]:
    payload = {
        "schema": "operationproof.howedo-binding.v1",
        "operation_id": operation_id,
        "snapshot_id": witness["snapshot_id"],
        "witness_digest": witness["witness_digest"],
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    return {**payload, "binding_digest": sha256_digest(payload), "attestation": "test-trusted"}


def accept_binding(binding: object) -> bool:
    return isinstance(binding, dict) and binding.get("attestation") == "test-trusted"


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


def adapt(action: str = "CONTINUE") -> EvidenceEnvelope:
    witness = howedo_witness(action)
    return HowedoWitnessAdapter.adapt(
        operation_id="op-1",
        witness=witness,
        binding=trusted_binding(witness),
        binding_verifier=accept_binding,
    )


def test_continue_maps_to_passing_continuity_evidence() -> None:
    witness = howedo_witness()
    binding = trusted_binding(witness)
    item = HowedoWitnessAdapter.adapt(
        operation_id="op-1",
        witness=witness,
        binding=binding,
        binding_verifier=accept_binding,
    )
    assert item.layer is Layer.CONTINUITY
    assert item.provider == "howedo"
    assert item.decision == "CONTINUE"
    assert item.verdict is Verdict.PASS
    assert item.metadata["howedo_witness_digest"] == witness["witness_digest"]
    assert item.metadata["binding_digest"] == binding["binding_digest"]


@pytest.mark.parametrize("action", ["PAUSE", "REVALIDATE", "ABORT", "RECOVER"])
def test_non_continue_actions_fail_closed(action: str) -> None:
    item = adapt(action)
    assert item.verdict is Verdict.FAIL
    assert item.decision == action


def test_tampered_howedo_witness_is_rejected() -> None:
    witness = howedo_witness()
    binding = trusted_binding(witness)
    witness["action"] = "ABORT"
    with pytest.raises(HowedoWitnessError, match="HOWEDO_WITNESS_DIGEST_MISMATCH"):
        HowedoWitnessAdapter.adapt(
            operation_id="op-1",
            witness=witness,
            binding=binding,
            binding_verifier=accept_binding,
        )


def test_unknown_howedo_action_is_rejected() -> None:
    witness = howedo_witness()
    binding = trusted_binding(witness)
    witness["action"] = "MAYBE"
    with pytest.raises(HowedoWitnessError, match="INVALID_HOWEDO_ACTION"):
        HowedoWitnessAdapter.adapt(
            operation_id="op-1",
            witness=witness,
            binding=binding,
            binding_verifier=accept_binding,
        )


def test_operation_transplant_is_rejected() -> None:
    witness = howedo_witness()
    binding = trusted_binding(witness, operation_id="op-1")
    with pytest.raises(HowedoWitnessError, match="BINDING_OPERATION_ID_MISMATCH"):
        HowedoWitnessAdapter.adapt(
            operation_id="op-2",
            witness=witness,
            binding=binding,
            binding_verifier=accept_binding,
        )


def test_missing_expiry_is_rejected() -> None:
    witness = howedo_witness()
    binding = trusted_binding(witness)
    binding["expires_at"] = None
    binding["binding_digest"] = sha256_digest(
        {
            "schema": binding["schema"],
            "operation_id": binding["operation_id"],
            "snapshot_id": binding["snapshot_id"],
            "witness_digest": binding["witness_digest"],
            "issued_at": binding["issued_at"],
            "expires_at": binding["expires_at"],
        }
    )
    with pytest.raises(HowedoWitnessError, match="INVALID_BINDING_EXPIRES_AT"):
        HowedoWitnessAdapter.adapt(
            operation_id="op-1",
            witness=witness,
            binding=binding,
            binding_verifier=accept_binding,
        )


def test_tampered_binding_digest_is_rejected() -> None:
    witness = howedo_witness()
    binding = trusted_binding(witness)
    binding["issued_at"] = "2029-01-01T00:00:00+00:00"
    with pytest.raises(HowedoWitnessError, match="BINDING_DIGEST_MISMATCH"):
        HowedoWitnessAdapter.adapt(
            operation_id="op-1",
            witness=witness,
            binding=binding,
            binding_verifier=accept_binding,
        )


def test_untrusted_binding_is_rejected() -> None:
    witness = howedo_witness()
    binding = trusted_binding(witness)
    with pytest.raises(HowedoWitnessError, match="UNTRUSTED_HOWEDO_BINDING"):
        HowedoWitnessAdapter.adapt(
            operation_id="op-1",
            witness=witness,
            binding=binding,
            binding_verifier=lambda _: False,
        )


def test_binding_verifier_error_fails_closed() -> None:
    witness = howedo_witness()
    binding = trusted_binding(witness)

    def explode(_: object) -> bool:
        raise RuntimeError("provider unavailable")

    with pytest.raises(HowedoWitnessError, match="BINDING_VERIFICATION_ERROR"):
        HowedoWitnessAdapter.adapt(
            operation_id="op-1",
            witness=witness,
            binding=binding,
            binding_verifier=explode,
        )


def test_howedo_evidence_composes_into_verified_pre_proof() -> None:
    continuity = adapt()
    evidence = [
        continuity if layer is Layer.CONTINUITY else generic_evidence(layer)
        for layer in PRE_LAYERS
    ]
    proof = build_pre_proof("op-1", evidence)
    assert proof["decision"] == "VERIFIED"
    assert verify_proof(proof).valid is True


def test_revalidate_witness_rejects_pre_proof() -> None:
    continuity = adapt("REVALIDATE")
    evidence = [
        continuity if layer is Layer.CONTINUITY else generic_evidence(layer)
        for layer in PRE_LAYERS
    ]
    proof = build_pre_proof("op-1", evidence)
    assert proof["decision"] == "REJECTED"
    assert "LAYER_FAIL:continuity" in proof["reason_codes"]
    assert verify_proof(proof).valid is True
