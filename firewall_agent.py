"""
Firewall AI Agent using Google GenAI SDK.
Features:
- Multi-turn follow-up chat session
- Data masking for enterprise privacy
- One-click Security & Health Audit
- Virtual Packet Policy Match Simulator
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
1. 分析問題：仔細理解使用者提出的網路故障或除錯問題（例如：連線中斷、特定時間點阻擋、介面 Down、高延遲、封包掉包、VPN 斷線、CPU 高、規則安全審查等）。
2. 自主排查：
   - 根據目標設備類型 (Palo Alto 或 Fortinet)，主動判斷需要調用哪些唯讀指令 (如 show, get, diagnose, test 等)。
   - 當排查「連線能否通行」或「命中哪條規則」時，主動利用模擬指令：
     * Palo Alto: `test security-policy-match from <src_zone> to <dst_zone> source <src_ip> destination <dst_ip> protocol <proto> destination-port <port>`
     * Fortinet: `diagnose firewall iprope lookup <src_ip> <src_port> <dst_ip> <dst_port> <protocol> <interface>`
   - 當進行「健康與安全審查 (Audit)」時，綜合檢查 CPU、記憶體、Session 總數比、預設路由、過寬規則。
3. 產生結構化診斷報告：
   - 【問題摘要與現象】
   - 【設備實際排查過程與數據】
   - 【根本原因分析 (Root Cause)】
   - 【建議解決方案與處置步驟】
   - 【建議修復腳本 (Draft Remediation CLI)】（提供供工程師參考的具體變更指令草稿）

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

    def run_investigation(self, prompt: str, is_followup: bool = False, max_iterations: int = 7) -> Generator[Dict[str, Any], None, None]:
        device_name = "Palo Alto Networks (PAN-OS)" if self.connector.device_type == "paloalto_panos" else "Fortinet (FortiOS)"

        if not self.chat:
            self._init_chat()
            if not self.chat:
                yield {"type": "error", "content": "無法初始化 AI 模型，請檢查 API Key 或網路連線。"}
                return

        masked_prompt = self.masking_engine.mask_text(prompt)

        if not is_followup:
            user_context = f"""
[設備資訊]
類型: {device_name}
IP: {self.masking_engine.mask_text(self.connector.host)}

[任務/問題]
{masked_prompt}

請開始排查。若需要設備即時狀態，請呼叫 execute_firewall_command。
"""
            current_message = user_context
            yield {"type": "status", "content": f"開始分析，目標設備：{device_name} ({self.connector.host})..."}
        else:
            current_message = f"[後續追問] {masked_prompt}"
            yield {"type": "status", "content": "收到追問，延續既有上下文深入分析..."}

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
                final_report = self.masking_engine.unmask_text(raw_report)
                yield {"type": "final_report", "content": final_report}
                break

            tool_responses = []
            for call in function_calls:
                fn_name = call.name
                args = dict(call.args) if call.args else {}

                if fn_name == "execute_firewall_command":
                    raw_cmd = args.get("command", "").strip()
                    actual_cmd = self.masking_engine.unmask_text(raw_cmd)
                    reason = self.masking_engine.unmask_text(args.get("reason", "未說明原因"))

                    yield {
                        "type": "tool_call",
                        "command": actual_cmd,
                        "reason": reason,
                        "iteration": iteration,
                    }

                    raw_output = self.connector.run_command(actual_cmd)
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
