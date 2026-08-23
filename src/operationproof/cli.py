from __future__ import annotations

import argparse
import json
from pathlib import Path

from .sdk import ProofDocumentError, parse_proof_json
from .verifier import verify_proof


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify OperationProof v1/v2 integrity and recorded semantics"
    )
    parser.add_argument("proof", type=Path)
    args = parser.parse_args()

    try:
        raw = args.proof.read_bytes()
        proof = parse_proof_json(raw)
    except OSError:
        output = {"valid": False, "reason_codes": ["PROOF_INPUT_READ_ERROR"]}
        print(json.dumps(output, sort_keys=True))
        return 1
    except ProofDocumentError as exc:
        output = {"valid": False, "reason_codes": [f"PROOF_INPUT:{exc}"]}
        print(json.dumps(output, sort_keys=True))
        return 1

    result = verify_proof(proof)
    output = {"valid": result.valid, "reason_codes": list(result.reason_codes)}
    print(json.dumps(output, sort_keys=True))
    return 0 if result.valid and proof.get("decision") == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
