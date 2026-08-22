from __future__ import annotations

import argparse
import json
from pathlib import Path

from .verifier import verify_proof


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an OperationProof v1 JSON record")
    parser.add_argument("proof", type=Path)
    args = parser.parse_args()

    proof = json.loads(args.proof.read_text(encoding="utf-8"))
    result = verify_proof(proof)
    output = {"valid": result.valid, "reason_codes": list(result.reason_codes)}
    print(json.dumps(output, sort_keys=True))
    return 0 if result.valid and proof.get("decision") == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
