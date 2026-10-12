"""
Firewall AI Agent using Google GenAI SDK.
Supports:
- Multi-turn follow-up chat session
- Data masking for enterprise privacy
- Automatic retry on 503/429
- Draft remediation CLI generator
"""

import os
import time
from typing import Generator, Dict, Any, Optional
from google import genai
from google.genai import types
from firewall_connector import FirewallConnector
from masking_engine import DataMaskingEngine

SYSTEM_INSTRUCTION = """
你是一位擁有 15 年以上經驗的資深網路架構與安全運維專家 (NetOps & SecOps Senior Specialist)，專精於 Palo Alto Networks (PAN-OS) 和 Fortinet (FortiOS) 防火牆。

【你的職責與工作流程】
1. 分析問題：仔細理解使用者提出的網路故障或除錯問題（例如：連線中斷、特定時間點阻擋、介面 Down、高延遲、封包掉包、VPN 斷線、CPU 高等）。
2. 自主排查：
   - 根據目標設備類型 (Palo Alto 或 Fortinet)，主動判斷需要調用哪些唯讀指令 (如 show, get, diagnose, test 等)。
   - 調用提供的工具 `execute_firewall_command` 來抓取當前狀態、路由表、介面計數器、Session 表、ARP 表或系統日誌。
   - 每次下指令時，保持精準且有目的性。如果一次查詢結果不足以定論，繼續調用下一條相關指令深入查驗（最多可連續排查 5 步）。
3. 產生診斷報告：
   - 當蒐集到足夠證據後，給出結構化、專業且易懂的繁體中文除錯報告。
   - 報告結構需包含：
     * 【問題摘要與現象】
     * 【設備實際排查過程與數據】（指出關鍵日誌行或指標）
     * 【根本原因分析 (Root Cause)】
     * 【建議解決方案與處置步驟】
     * 【建議修復腳本 (Draft Remediation CLI)】（若適用，提供供工程師參考的具體 CLI 配置指令草稿，並註明需人工確認後執行）

【安全準則】
- 只能使用唯讀與診斷指令。不可執行任何 `set`, `config`, `delete`, `reboot`, `restart`, `commit` 等會變更設備狀態的危險指令。
"""

class FirewallAgent:
    def __init__(
        self,
        connector: FirewallConnector,
        api_key: str = None,
        model: str = "gemini-3.8-flash",
        enable_masking: bool = True
    ):
        self.connector = connector
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model = model
        self.masking_engine = DataMaskingEngine(enabled=enable_masking)
        if not self.api_key:
            raise ValueError("請提供 Gemini API Key！")

        self.client = genai.Client(api_key=self.api_key)
        self.chat = None
        self._init_chat()

    def _init_chat(self):
        device_name = "Palo Alto Networks (PAN-OS)" if self.connector.device_type == "paloalto_panos" else "Fortinet (FortiOS)"
        
        tool_declaration = {
            "name": "execute_firewall_command",
            "description": f"在目前的 {device_name} 設備上執行唯讀診斷指令並獲取輸出。",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "command": {
                        "type": "STRING",
                        "description": f"要執行的完整 CLI 指令。PA 請用 show/test/debug 開頭；Fortinet 請用 get/show/diagnose 開頭。嚴禁修改設定之指令。",
                    },
                    "reason": {
                        "type": "STRING",
                        "description": "為什麼要執行這條指令的簡短說明，讓使用者了解除錯思路。",
                    }
                },
                "required": ["command", "reason"],
            }
        }

        candidate_models = [self.model, "gemini-2.0-flash", "gemini-1.5-flash"]
        for m in candidate_models:
            try:
                self.chat = self.client.chats.create(
                    model=m,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_INSTRUCTION,
                        tools=[types.Tool(function_declarations=[types.FunctionDeclaration(**tool_declaration)])],
                        temperature=0.2,
                    )
                )
                self.model = m
                break
            except Exception:
                continue

    def _send_message_with_retry(self, message, max_retries=3):
        delay = 2
        last_error = None
        for attempt in range(max_retries):
            try:
                return self.chat.send_message(message)
            except Exception as e:
                err_str = str(e)
                if "503" in err_str or "429" in err_str or "UNAVAILABLE" in err_str:
                    last_error = e
                    time.sleep(delay)
                    delay *= 1.5
                    continue
                raise e
        raise last_error

    def run_investigation(self, prompt: str, is_followup: bool = False, max_iterations: int = 6) -> Generator[Dict[str, Any], None, None]:
        device_name = "Palo Alto Networks (PAN-OS)" if self.connector.device_type == "paloalto_panos" else "Fortinet (FortiOS)"

        if not self.chat:
            self._init_chat()
            if not self.chat:
                yield {"type": "error", "content": "無法初始化 AI 模型，請檢查 API Key 或網路連線。"}
                return

        # 脫敏處理：將使用者提問中的機敏 IP 轉為標籤
        masked_prompt = self.masking_engine.mask_text(prompt)

        if not is_followup:
            user_context = f"""
[設備資訊]
類型: {device_name}
IP: {self.masking_engine.mask_text(self.connector.host)}

[排查問題]
{masked_prompt}

請開始診斷。若需要設備即時狀態，請呼叫 execute_firewall_command。
"""
            current_message = user_context
            yield {"type": "status", "content": f"開始分析問題，目標設備：{device_name} ({self.connector.host})..."}
        else:
            current_message = f"[後續追問] {masked_prompt}"
            yield {"type": "status", "content": "收到後續追問，延續既有設備上下文深入分析..."}

        iteration = 0
        while iteration < max_iterations:
            iteration += 1

            try:
                response = self._send_message_with_retry(current_message)
            except Exception as e:
                yield {"type": "error", "content": f"AI 模型暫時繁忙: {str(e)}。"}
                return

            candidate = response.candidates[0]
            model_content = candidate.content

            function_calls = [part.function_call for part in model_content.parts if part.function_call]

            if not function_calls:
                text_parts = [part.text for part in model_content.parts if part.text]
                raw_report = "\n".join(text_parts)
                # 反向還原：將代號還原回真實 IP 給使用者閱讀
                final_report = self.masking_engine.unmask_text(raw_report)
                yield {"type": "final_report", "content": final_report}
                break

            tool_responses = []
            for call in function_calls:
                fn_name = call.name
                args = dict(call.args) if call.args else {}

                if fn_name == "execute_firewall_command":
                    # AI 產生的指令可能帶有 [NET_IP_1]，執行前必須還原成真實 IP
                    raw_cmd = args.get("command", "").strip()
                    actual_cmd = self.masking_engine.unmask_text(raw_cmd)
                    reason = self.masking_engine.unmask_text(args.get("reason", "未說明原因"))

                    yield {
                        "type": "tool_call",
                        "command": actual_cmd,
                        "reason": reason,
                        "iteration": iteration,
                    }

                    # 從防火牆抓取資料
                    raw_output = self.connector.run_command(actual_cmd)

                    # 脫敏處理：回傳給 AI 前將設備輸出中的 IP 遮罩
                    masked_output = self.masking_engine.mask_text(raw_output)

                    if len(masked_output) > 5000:
                        clipped_output = masked_output[:3000] + "\n\n...[日誌過長，已截斷中間部分]...\n\n" + masked_output[-1500:]
                    else:
                        clipped_output = masked_output

                    yield {
                        "type": "tool_result",
                        "command": actual_cmd,
                        "output_preview": raw_output[:600] + ("..." if len(raw_output) > 600 else ""),
                    }

                    tool_responses.append(
                        types.Part.from_function_response(
                            name=fn_name,
                            response={"result": clipped_output}
                        )
                    )

            current_message = tool_responses
