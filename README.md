# 萬用防火牆 AI 自動排錯助理 (Firewall NetOps AI Troubleshooter)

這是一個專為 **Palo Alto Networks (PAN-OS)** 與 **Fortinet (FortiOS)** 設計的智慧維運排錯工具。
採用 **ReAct (Reasoning + Acting) Agent** 架構，由大型語言模型 (LLM) 根據使用者提出的任何自然語言問題，**自主決定**下達唯讀診斷指令（如查詢 Traffic Log、介面狀態、光衰、路由表、計數器等），並分析回傳的 Raw Output 給出根本原因與修復建議。

---

## 🎯 專案演進與上下文記錄 (Context & History)

為了讓你在不同電腦間接續開發與使用，以下記錄本專案已解決的關鍵挑戰與架構決策：

1. **萬用排查邏輯 (ReAct Agent)**：
   - 不再依賴固定規則或寫死的指令對應。
   - LLM（Gemini 3.8 Flash）根據自然語言問題（如介面 down、連線阻擋、CPU 負載、VPN 斷線）自主推理，並發動多輪指令查詢。
2. **唯讀安全防護機制 (Safeguard)**：
   - [firewall_connector.py](file:///c:/Users/user/.gemini/antigravity/project/防火牆除錯工具/firewall_connector.py) 內建黑名單與白名單，徹底封鎖 `config`, `set`, `delete`, `reboot` 等變更指令。
3. **SSH 舊版演算法相容層 (Paramiko 5.0 相容)**：
   - 解決了企業級防火牆（FortiGate / Palo Alto）連線時常見的：
     - `Incompatible ssh peer (no acceptable host key)`
     - `KeyError: 'ssh-rsa'`（Paramiko 5.0 移除 ssh-rsa 映射）
     - `Signature verification (ssh-rsa) failed`（RFC 8332 SHA-256 簽章適配）
   - 內建補丁與演算法註冊，確保直接 SSH 登入企業設備成功。
4. **API 高峰自動重試 (503 / 429 Resilience)**：
   - [firewall_agent.py](file:///c:/Users/user/.gemini/antigravity/project/防火牆除錯工具/firewall_agent.py) 內建指數退避重試與模型相容支援，避免短暫連線尖峰造成中斷。
5. **資安考量與合規**：
   - 排查主要傳輸維運狀態與五元組/日誌 Header，不涉及 HTTPS 加密 Payload。
   - 建議使用付費/商業版 API Key（符合合約「不保留、不用於模型訓練」）。

---

## 🚀 快速啟動指南

### 1. 安裝環境相依套件
在另一台電腦拉取代碼後，請確保安裝以下套件：
```bash
pip install fastapi uvicorn netmiko paramiko google-genai pydantic
```

### 2. 啟動 Web UI 網頁介面 (推薦)
```bash
python web_app.py
```
打開瀏覽器訪問：**`http://127.0.0.1:8000`**

### 3. 使用 CLI 命令列介面
```bash
python cli_app.py
```

---

## 💡 常用測試 Prompt 範例

- **介面故障**：`PA 防火牆的 ethernet1/1 在下午 14:00 為何會 down？請檢查實體層、光衰與系統事件日誌。`
- **連線阻擋**：`為什麼 192.168.1.1 在 14:00 連不到 192.168.2.2？請檢查安全規則、Traffic Log 與路由。`
- **系統負載**：`檢查當前防火牆系統健康狀態、CPU 使用率與前五大 Session。`
- **路由確認**：`確認到 8.8.8.8 的路由下一跳 (Next-hop) 與出口介面。`
