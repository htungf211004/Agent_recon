import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from src.main import app


async def main():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://audit.local") as client:
        results = {}
        for path in ["/health", "/api/v1/status"]:
            response = await client.get(path)
            results[path] = {"status": response.status_code, "body": response.json()}
        with patch("src.services.llm.get_llm") as llm:
            response = await client.post("/api/v1/chat", json={"message": "audit local demo"})
            results["chat"] = {"status": response.status_code, "body": response.json(), "get_llm_calls": llm.call_count}
        response = await client.post("/api/v1/chat", json={"message": ""})
        results["empty_chat"] = {"status": response.status_code}
        with patch("src.api.routes.agent.ainvoke", new=AsyncMock(side_effect=RuntimeError("AUDIT_SYNTHETIC_ERROR"))):
            response = await client.post("/api/v1/chat", json={"message": "audit failure"})
            results["synthetic_failure"] = {"status": response.status_code, "body": response.json()}
        results["business_routes"] = sorted(app.openapi()["paths"])
        results["method"] = "In-process ASGI requests only; no external LLM or pentest targets called."
        target = Path("tmp/team-plan/audit-runtime.json")
        target.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(results, ensure_ascii=False))


asyncio.run(main())
