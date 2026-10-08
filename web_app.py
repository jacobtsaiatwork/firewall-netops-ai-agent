"""
FastAPI Server for Firewall NetOps AI Troubleshooter.
"""

import os
import json
import asyncio
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from firewall_connector import FirewallConnector
from firewall_agent import FirewallAgent

app = FastAPI(title="Firewall NetOps AI Troubleshooter")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionTestRequest(BaseModel):
    device_type: str
    host: str
    username: str
    password: str
    port: int = 22

class InvestigateRequest(BaseModel):
    api_key: str
    device_type: str
    host: str
    username: str
    password: str
    port: int = 22
    prompt: str

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html_file = os.path.join(os.path.dirname(__file__), "index.html")
    with open(html_file, "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/test-connection")
async def test_connection(req: ConnectionTestRequest):
    connector = FirewallConnector(
        device_type=req.device_type,
        host=req.host,
        username=req.username,
        password=req.password,
        port=req.port,
        timeout=10
    )
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, connector.connect)
        connector.close()
        return {"success": True, "message": "SSH 驗證通過，設備回應正常"}
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.post("/api/investigate")
async def investigate(req: InvestigateRequest):
    connector = FirewallConnector(
        device_type=req.device_type,
        host=req.host,
        username=req.username,
        password=req.password,
        port=req.port,
        timeout=25
    )

    async def event_generator():
        try:
            agent = FirewallAgent(
                connector=connector,
                api_key=req.api_key,
                model="gemini-3.8-flash"
            )

            for step in agent.run_investigation(req.prompt):
                data = json.dumps(step, ensure_ascii=False)
                yield f"data: {data}\n\n"
                await asyncio.sleep(0.05)

        except Exception as e:
            err_data = json.dumps({"type": "error", "content": str(e)}, ensure_ascii=False)
            yield f"data: {err_data}\n\n"
        finally:
            connector.close()

    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web_app:app", host="127.0.0.1", port=8000, reload=True)
