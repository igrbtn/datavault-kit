import json

import httpx
import pytest

from datavault.gateway import GatewayConfig, GatewayError, ModelGateway, Target


def _cfg(tmp_path, base="http://127.0.0.1:1234/v1", extract="[lm:bad-model, ol:good-model]"):
    p = tmp_path / "m.yaml"
    p.write_text(
        f"providers:\n  lm: {{base_url: {base}}}\n"
        "  ol: {base_url: http://localhost:11434/v1, kind: ollama}\n"
        f"routes:\n  extract: {extract}\n"
        "embeddings: [ol:emb]\n"
    )
    return GatewayConfig.load(p)


def test_rejects_non_loopback(tmp_path):
    with pytest.raises(GatewayError):
        _cfg(tmp_path, base="http://192.168.0.10:1234/v1")
    with pytest.raises(GatewayError):
        _cfg(tmp_path, base="https://api.example.com/v1")


def test_target_parse_keeps_model_colons():
    t = Target.parse("ollama:qwen2.5:7b")
    assert (t.provider, t.model) == ("ollama", "qwen2.5:7b")


def test_project_config_loads():
    cfg = GatewayConfig.load()
    assert set(cfg.routes) >= {"ner", "extract", "classify", "heavy"}


def _transport(seen, remote=()):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/tags":
            models = [{"name": "good-model"}, {"name": "emb"}]
            models += [{"name": n, "remote_host": "https://ollama.com:443"} for n in remote]
            return httpx.Response(200, json={"models": models})
        if req.url.path.endswith("/models"):
            if req.url.port == 1234:
                return httpx.Response(200, json={"data": [{"id": "other"}]})
            return httpx.Response(200, json={"data": [{"id": "good-model"}, {"id": "emb"}]})
        body = json.loads(req.content)
        seen.append(body)
        if req.url.path.endswith("/embeddings"):
            return httpx.Response(200, json={"data": [{"index": 0, "embedding": [0.1, 0.2]}]})
        if body["model"] == "bad-model":
            return httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"n": 3}'}}]})
    return httpx.MockTransport(handler)


def test_fallback_and_structured_request(tmp_path):
    seen = []
    gw = ModelGateway(_cfg(tmp_path), httpx.Client(transport=_transport(seen)))
    data, used = gw.complete_json("extract", [{"role": "user", "content": "x"}],
                                  {"type": "object", "properties": {"n": {"type": "integer"}}})
    assert data == {"n": 3} and str(used) == "ol:good-model"
    assert seen[0]["response_format"]["type"] == "json_schema"
    assert seen[0]["temperature"] == 0


def test_health_and_embed(tmp_path):
    gw = ModelGateway(_cfg(tmp_path), httpx.Client(transport=_transport([])))
    h = gw.health()
    assert all(p["up"] for p in h["providers"])
    assert [r["available"] for r in h["routes"]["extract"]] == [False, True]
    vecs, _ = gw.embed(["a"])
    assert vecs == [[0.1, 0.2]]


def test_unknown_task(tmp_path):
    gw = ModelGateway(_cfg(tmp_path), httpx.Client(transport=_transport([])))
    with pytest.raises(GatewayError):
        gw.complete_json("nope", [], {})


def test_rejects_cloud_model_routes(tmp_path):
    for bad in ("[ol:gpt-oss:120b-cloud]", "[ol:qwen3:cloud]", "[ol:Cloud-x]"):
        with pytest.raises(GatewayError, match="cloud"):
            _cfg(tmp_path, extract=bad)
    _cfg(tmp_path, extract="[ol:cloudflare-tuned]")  # substring alone is fine


def test_renamed_cloud_model_blocked_at_runtime(tmp_path):
    seen = []
    gw = ModelGateway(_cfg(tmp_path, extract="[ol:good-model]"),
                      httpx.Client(transport=_transport(seen, remote=["good-model"])))
    with pytest.raises(GatewayError):
        gw.complete_json("extract", [{"role": "user", "content": "secret"}], {})
    assert seen == []  # nothing was sent


def test_health_flags_cloud_models(tmp_path):
    gw = ModelGateway(_cfg(tmp_path), httpx.Client(transport=_transport([], remote=["x-cloud"])))
    h = gw.health()
    assert h["warnings"] and "cloud" in h["warnings"][0]


def test_embed_pinned_model_has_no_fallback(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text("providers:\n  ol: {base_url: http://localhost:11434/v1, kind: ollama}\n"
                 "routes: {}\nembeddings: [ol:dead, ol:emb]\n")
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "dead"}, {"name": "emb"}]})
        body = json.loads(req.content)
        seen.append(body["model"])
        if body["model"] == "dead":
            return httpx.Response(400, json={"error": "oom"})
        return httpx.Response(200, json={"data": [{"index": 0, "embedding": [1.0]}]})

    gw = ModelGateway(GatewayConfig.load(p), httpx.Client(transport=httpx.MockTransport(handler)))
    _, used = gw.embed(["a"])
    assert str(used) == "ol:emb"
    with pytest.raises(GatewayError):
        gw.embed(["a"], only="ol:dead")
    assert seen == ["dead", "emb", "dead"]


def test_json_answer_in_reasoning_content(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text("providers:\n  lm: {base_url: http://127.0.0.1:1234/v1}\n"
                 "routes: {heavy: [lm:think]}\nembeddings: []\n")

    def handler(req: httpx.Request) -> httpx.Response:
        msg = {"role": "assistant", "content": "", "reasoning_content": '{"n": 1}'}
        return httpx.Response(200, json={"choices": [{"message": msg}]})

    gw = ModelGateway(GatewayConfig.load(p), httpx.Client(transport=httpx.MockTransport(handler)))
    data, _ = gw.complete_json("heavy", [], {"type": "object"})
    assert data == {"n": 1}
