import json

import anyio
import httpx
from conftest import IVANOV
from mcp import Client

from datavault.gateway import GatewayConfig, ModelGateway
from datavault.server import build_server


def _call(server, name, args=None):
    async def run():
        async with Client(server) as c:
            tools = [t.name for t in (await c.list_tools()).tools]
            res = await c.call_tool(name, args or {})
            return tools, res
    return anyio.run(run)


def _payload(res):
    if res.structured_content is not None:
        return res.structured_content
    return json.loads(res.content[0].text)


def test_tools_listed_and_cases(case):
    tools, res = _call(build_server(), "cases")
    assert set(tools) == {"cases", "schema", "status", "models", "search", "read", "extract",
                          "aggregate", "describe", "rows", "render", "out_files", "exec"}
    data = _payload(res)
    assert data["cases"][0]["name"] == "demo-case"
    assert data["cases"][0]["sources"] == 4


def test_schema_over_mcp_leaks_nothing(case):
    _, res = _call(build_server(), "schema", {"case": "demo-case"})
    srcs = _payload(res)["sources"]
    for s in srcs:
        _, r = _call(build_server(), "schema", {"case": "demo-case", "source": s["id"]})
        assert IVANOV not in json.dumps(_payload(r), ensure_ascii=False)


def test_schema_bad_case(home):
    _, res = _call(build_server(), "schema", {"case": "../etc"})
    assert "error" in _payload(res)


def test_models_tool(tmp_path):
    def handler(req):
        return httpx.Response(200, json={"data": []})
    gw = ModelGateway(GatewayConfig.load(), httpx.Client(transport=httpx.MockTransport(handler)))
    _, res = _call(build_server(gw), "models")
    assert "routes" in _payload(res)


def test_structure_tools_are_audited(home):
    import sqlite3

    from test_p2 import p2case as make_p2case

    from datavault.ingest import store_path
    p2case = make_p2case.__wrapped__(home)

    async def run():
        async with Client(build_server()) as c:
            await c.call_tool("status", {"case": p2case.name})
            await c.call_tool("schema", {"case": p2case.name, "source": "all"})
    anyio.run(run)
    rows = sqlite3.connect(store_path(p2case)).execute(
        "SELECT tool FROM access ORDER BY rowid").fetchall()
    assert [r[0] for r in rows][-2:] == ["status", "schema"]
