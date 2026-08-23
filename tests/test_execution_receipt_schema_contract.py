import json
from pathlib import Path

from operationproof.canonical import DIGEST_RE


def test_execution_receipt_schema_matches_runtime_contract() -> None:
    schema = json.loads(Path("schemas/execution-receipt.v1.schema.json").read_text())

    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema"]["const"] == "operationproof.execution-receipt.v1"
    assert set(schema["properties"]["provider"]["enum"]) == {"sandcloud", "caser"}
    assert set(schema["properties"]["status"]["enum"]) == {
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
        "UNKNOWN",
    }
    assert schema["$defs"]["sha256"]["pattern"] == DIGEST_RE.pattern
    assert set(schema["required"]) == {
        "schema",
        "provider",
        "receipt_id",
        "operation_id",
        "pre_proof_digest",
        "status",
        "result_digest",
        "started_at",
        "completed_at",
        "receipt_digest",
    }
