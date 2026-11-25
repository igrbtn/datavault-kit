"""Live smoke against local runtimes: pytest -m live"""
import pytest

from datavault.gateway import GatewayConfig, ModelGateway

pytestmark = pytest.mark.live


def test_live_classify_structured():
    gw = ModelGateway(GatewayConfig.load())
    schema = {
        "type": "object",
        "properties": {"label": {"type": "string", "enum": ["invoice", "contract", "other"]}},
        "required": ["label"],
        "additionalProperties": False,
    }
    data, used = gw.complete_json(
        "classify",
        [{"role": "system", "content": "Classify the document type."},
         {"role": "user", "content": "Invoice #42. Total due: 100 USD. Pay by 2026-12-01."}],
        schema, max_tokens=64,
    )
    assert data["label"] == "invoice", (data, str(used))


def test_live_embeddings():
    gw = ModelGateway(GatewayConfig.load())
    vecs, _ = gw.embed(["hello", "world"])
    assert len(vecs) == 2 and len(vecs[0]) > 100
