"""
FastAPI Server for Firewall NetOps AI Troubleshooter.
Features:
- Dynamic model selection (gemini-1.5-flash, 1.5-pro, 2.0-flash)
- Session lifecycle & TTL cleanup (prevents memory leak & SSH lingering)
- AES Fernet encrypted device vault
"""

import os
import time
import json
import asyncio
from typing import Optional, Dict
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from firewall_connector import FirewallConnector
from firewall_agent import FirewallAgent
from vault_manager import DeviceVaultManager

app = FastAPI(title="Firewall NetOps AI Troubleshooter")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 帶有最後訪問時間戳記的 Session 快取
active_sessions: Dict[str, Dict] = {}
SESSION_TTL_SECONDS = 1800  # 30 分鐘無活動自動釋放

def _cleanup_expired_sessions():
    """定期清理超時 Session，中斷 SSH 並釋放記憶體"""
    now = time.time()
    expired = []
    for sid, data in active_sessions.items():
        if now - data.get("last_active", 0) > SESSION_TTL_SECONDS:
            expired.append(sid)
    for sid in expired:
        try:
            agent = active_sessions[sid].get("agent")
            if agent and agent.connector:
                agent.connector.close()
        except Exception:
            pass
        active_sessions.pop(sid, None)

class ConnectionTestRequest(BaseModel):
    device_type: str
    host: str
    username: str
    password: str
    port: int = 22
    timeout: Optional[int] = 15

class InvestigateRequest(BaseModel):
    session_id: str
    api_key: str
    device_type: str
    host: str
    username: str
    password: str
    port: int = 22
    prompt: str
    model: Optional[str] = "gemini-1.5-flash"
    max_iterations: Optional[int] = 4
    timeout: Optional[int] = 25
    enable_masking: bool = True
    is_followup: bool = False

class DeviceProfile(BaseModel):
    name: str
    device_type: str
    host: str
    username: str
    password: Optional[str] = ""
    port: int = 22

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html_file = os.path.join(os.path.dirname(__file__), "index.html")
    with open(html_file, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/vault/devices")
async def list_vault_devices():
    return DeviceVaultManager.load_devices()

@app.post("/api/vault/devices")
async def save_vault_device(profile: DeviceProfile):
    updated = DeviceVaultManager.save_device(profile.model_dump())
    return {"success": True, "devices": updated}

@app.delete("/api/vault/devices")
async def delete_vault_device(host: str, port: int = 22):
    updated = DeviceVaultManager.delete_device(host, port)
    return {"success": True, "devices": updated}

@app.post("/api/session/close")
async def close_session(session_id: str):
    """前端點擊新對話時主動關閉連線"""
    data = active_sessions.pop(session_id, None)
    if data and data.get("agent"):
        try:
            data["agent"].connector.close()
        except Exception:
            pass
    return {"success": True}

@app.post("/api/test-connection")
async def test_connection(req: ConnectionTestRequest):
    connector = FirewallConnector(
        device_type=req.device_type,
        host=req.host,
        username=req.username,
        password=req.password,
        port=req.port,
        timeout=req.timeout or 15
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
    _cleanup_expired_sessions()

    session_data = active_sessions.get(req.session_id)
    agent = session_data.get("agent") if session_data else None

    # 如果需要新建 Agent 或更換連線參數
    if not agent or not req.is_followup:
        # 若已有舊連線先關閉
        if agent and agent.connector:
            try:
                agent.connector.close()
            except Exception:
                pass

        connector = FirewallConnector(
            device_type=req.device_type,
            host=req.host,
            username=req.username,
            password=req.password,
            port=req.port,
            timeout=req.timeout or 25
        )
        agent = FirewallAgent(
            connector=connector,
            api_key=req.api_key,
            model=req.model or "gemini-1.5-flash",
            enable_masking=req.enable_masking
        )
        active_sessions[req.session_id] = {
            "agent": agent,
            "last_active": time.time()
        }
    else:
        active_sessions[req.session_id]["last_active"] = time.time()

    async def event_generator():
        try:
            for step in agent.run_investigation(
                req.prompt,
                is_followup=req.is_followup,
                max_iterations=req.max_iterations or 4
            ):
                data = json.dumps(step, ensure_ascii=False)
                yield f"data: {data}\n\n"
                await asyncio.sleep(0.04)
        except Exception as e:
            err_data = json.dumps({"type": "error", "content": str(e)}, ensure_ascii=False)
            yield f"data: {err_data}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web_app:app", host="127.0.0.1", port=8000, reload=True)
