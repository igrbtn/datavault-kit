import json

import anyio
from mcp import Client

from datavault.server import build_server


def call(name, args=None, server=None):
    async def run():
        async with Client(server or build_server()) as c:
            return await c.call_tool(name, args or {})
    res = anyio.run(run)
    if res.structured_content is not None:
        return res.structured_content
    return json.loads(res.content[0].text)
