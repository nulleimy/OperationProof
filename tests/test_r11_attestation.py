from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import operationproof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict


def _key_material() -> tuple[bytes, bytes]:
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def _subject(operation_id: str = "op-r11") -> operationproof.OperationSubject:
    return operationproof.OperationSubject(
        operation_id=operation_id,
        actor_digest=sha256_digest({"actor": "alice"}),
        intent_digest=sha256_digest({"intent": "deploy"}),
        target_digest=sha256_digest({"target": "service-a"}),
        state_digest=sha256_digest({"state": "revision-1"}),
    )


def _pre_proof(operation_id: str = "op-r11") -> dict[str, object]:
    subject = _subject(operation_id)
    evidence = [
        EvidenceEnvelope(
            layer=layer,
            provider=f"r11:{layer.value}",
            operation_id=operation_id,
            decision="native-ok",
            verdict=Verdict.PASS,
            subject_digest=subject.digest,
            evidence_digest=sha256_digest({"evidence": layer.value, "operation": operation_id}),
            issued_at="2026-08-24T01:00:00+00:00",
            expires_at="2030-01-01T00:00:00+00:00",
        )
        for layer in PRE_LAYERS
    ]
    return operationproof.build_pre_proof(operation_id, evidence, subject=subject)


def _signer_and_registry(key_id: str = "r11-key") -> tuple[operationproof.Ed25519AttestationSigner, operationproof.AttestationTrustRegistry]:
    private_bytes, public_bytes = _key_material()
    signer = operationproof.Ed25519AttestationSigner(key_id=key_id, private_key=private_bytes)
    registry = operationproof.AttestationTrustRegistry()
    registry.register_ed25519_public_key(key_id=key_id, public_key=public_bytes)
    return signer, registry


def test_ed25519_signed_provenance_round_trip() -> None:
    signer, registry = _signer_and_registry()
    proof = _pre_proof()
    statement = operationproof.build_proof_provenance_statement(
        proof,
        producer="operationproof.test",
        issued_at="2026-08-24T01:01:00+00:00",
        metadata={"environment": "test"},
    )

    attestation = operationproof.sign_provenance_statement(statement, signer)
    result = operationproof.verify_signed_attestation(attestation, registry)

    assert statement["artifact_type"] == "PRE_PROOF"
    assert statement["artifact_digest"] == proof["proof_digest"]
    assert statement["subject_digest"] == proof["subject_digest"]
    assert result.valid is True
    assert result.trusted is True
    assert result.reason_codes == ()


def test_tampered_statement_cannot_be_rescued_by_rehashing_outer_attestation() -> None:
    signer, registry = _signer_and_registry()
    statement = operationproof.build_proof_provenance_statement(
        _pre_proof(),
        producer="operationproof.test",
        issued_at="2026-08-24T01:01:00+00:00",
    )
    attestation = operationproof.sign_provenance_statement(statement, signer)
    attestation["statement"]["producer"] = "attacker"
    attestation["attestation_digest"] = sha256_digest(
        {key: value for key, value in attestation.items() if key != "attestation_digest"}
    )

    result = operationproof.verify_signed_attestation(attestation, registry)

    assert result.valid is False
    assert any("PROVENANCE_STATEMENT_DIGEST_MISMATCH" in code for code in result.reason_codes)


def test_wrong_key_fails_closed() -> None:
    signer, _registry = _signer_and_registry("signing-key")
    _private, unrelated_public = _key_material()
    registry = operationproof.AttestationTrustRegistry()
    registry.register_ed25519_public_key(key_id="signing-key", public_key=unrelated_public)
    statement = operationproof.build_provenance_statement(
        operation_id="op-r11",
        subject_digest=_subject().digest,
        artifact_type=operationproof.ProvenanceArtifactType.GATEWAY_FORWARD,
        artifact_digest=sha256_digest({"gateway": "forward"}),
        producer="gateway-a",
        issued_at="2026-08-24T01:02:00+00:00",
    )
    attestation = operationproof.sign_provenance_statement(statement, signer)

    result = operationproof.verify_signed_attestation(attestation, registry)

    assert result.valid is False
    assert result.trusted is False
    assert "ATTESTATION_SIGNATURE_INVALID" in result.reason_codes


def test_attestation_chain_requires_exact_operation_subject_and_predecessor() -> None:
    signer, registry = _signer_and_registry()
    subject = _subject()
    first_statement = operationproof.build_provenance_statement(
        operation_id=subject.operation_id,
        subject_digest=subject.digest,
        artifact_type=operationproof.ProvenanceArtifactType.PRE_PROOF,
        artifact_digest=sha256_digest({"proof": "pre"}),
        producer="planner",
        issued_at="2026-08-24T01:00:00+00:00",
    )
    first = operationproof.sign_provenance_statement(first_statement, signer)
    second_statement = operationproof.build_provenance_statement(
        operation_id=subject.operation_id,
        subject_digest=subject.digest,
        artifact_type=operationproof.ProvenanceArtifactType.GATEWAY_FORWARD,
        artifact_digest=sha256_digest({"gateway": "forward"}),
        producer="gateway",
        issued_at="2026-08-24T01:01:00+00:00",
        predecessor_attestation_digest=first["attestation_digest"],
    )
    second = operationproof.sign_provenance_statement(second_statement, signer)

    valid = operationproof.verify_attestation_chain([first, second], registry)
    spliced_statement = operationproof.build_provenance_statement(
        operation_id=subject.operation_id,
        subject_digest=subject.digest,
        artifact_type=operationproof.ProvenanceArtifactType.EXECUTION_RECEIPT,
        artifact_digest=sha256_digest({"execution": "receipt"}),
        producer="executor",
        issued_at="2026-08-24T01:02:00+00:00",
        predecessor_attestation_digest=sha256_digest({"wrong": "predecessor"}),
    )
    spliced = operationproof.sign_provenance_statement(spliced_statement, signer)
    invalid = operationproof.verify_attestation_chain([first, spliced], registry)

    assert valid.valid is True
    assert valid.trusted is True
    assert invalid.valid is False
    assert "ATTESTATION[1]:PREDECESSOR_DIGEST_MISMATCH" in invalid.reason_codes


def test_proof_provenance_rejects_tampered_proof() -> None:
    proof = _pre_proof()
    proof["operation_id"] = "tampered-operation"

    try:
        operationproof.build_proof_provenance_statement(
            proof,
            producer="operationproof.test",
            issued_at="2026-08-24T01:01:00+00:00",
        )
    except operationproof.AttestationError as exc:
        assert str(exc).startswith("INVALID_PROOF_FOR_PROVENANCE:")
    else:
        raise AssertionError("tampered proof must not become provenance")
