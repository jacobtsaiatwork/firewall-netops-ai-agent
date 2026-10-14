"""
Firewall AI Agent using Google GenAI SDK.
Features:
- Guaranteed conversational responses (No raw CLI dumps without explanation)
- Forced final synthesis when investigation limit is reached
- Explains findings like a human NetOps Senior Consultant
"""

import os
import time
from typing import Generator, Dict, Any, Optional
from google import genai
from google.genai import types
from firewall_connector import FirewallConnector
from masking_engine import DataMaskingEngine

SYSTEM_INSTRUCTION = """
你是一位資深的網路安全與防火牆維運顧問 (Senior NetOps & SecOps Consultant)。
你的目標是：【用自然語言與工程師對話，深入排錯並直接指出問題根因與具體解法】。

【對話與溝通準則 - 最重要】
1. 切勿只當指令轉發器！設備輸出的生硬日誌（CLI raw output）只是你的除錯依據，使用者需要的是你「消化後的專業解釋與結論」。
2. 每次回答必須給出明確的【人類大白話結論】：
   - 為什麼連不上？（例如：被哪條 Policy 擋了？還是 VPN 隧道斷了？還是路由沒有下一跳？）
   - 在哪一個環節出錯？
   - 具體該去哪裡修改（GUI 路徑或 CLI 指令）？
3. 如果使用者問「結果是什麼？」或「這是什麼意思？」，請直接針對已收集的日誌進行詳細白話解釋，不要重新盲目下指令。

【自主排查能力】
- 針對 Palo Alto / Fortinet，你可以調用 `execute_firewall_command` 抓取路由表、安全原則匹配、VPN SA 狀態、介面計數器或系統日誌。
- 每次下指令時，請保持精準。最多執行 5 步調查，若足夠或已到步數上限，必須立即整理產出最終結論。
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
                        "description": "要執行的完整 CLI 指令。PA 請用 show/test/debug 開頭；Fortinet 請用 get/show/diagnose 開頭。嚴禁修改設定之指令。",
                    },
                    "reason": {
                        "type": "STRING",
                        "description": "為什麼要執行這條指令的簡短說明。",
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
                        temperature=0.3,
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

    def run_investigation(self, prompt: str, is_followup: bool = False, max_iterations: int = 5) -> Generator[Dict[str, Any], None, None]:
        device_name = "Palo Alto Networks (PAN-OS)" if self.connector.device_type == "paloalto_panos" else "Fortinet (FortiOS)"

        if not self.chat:
            self._init_chat()
            if not self.chat:
                yield {"type": "error", "content": "無法初始化 AI 模型，請檢查 API Key 或網路連線。"}
                return

        masked_prompt = self.masking_engine.mask_text(prompt)

        # 判斷使用者是否只是在問總結或解釋
        prompt_lower = prompt.lower()
        is_asking_summary = any(k in prompt_lower for k in ["結果", "結論", "為什麼", "這代表", " summary", "結論是什麼", "結果是什麼"])

        if not is_followup:
            user_context = f"""
[目標設備] {device_name} ({self.masking_engine.mask_text(self.connector.host)})
[排查問題] {masked_prompt}

請開始排查。若需要設備即時狀態，請呼叫 execute_firewall_command。調查完成後，必須給出結構化中文診斷報告與建議。
"""
            current_message = user_context
            yield {"type": "status", "content": f"開始分析問題，目標設備：{device_name} ({self.connector.host})..."}
        else:
            if is_asking_summary:
                current_message = f"[使用者提問] {masked_prompt}\n請不要再下新的指令。請立即根據上一輪所有指令收集到的設備回傳輸出，用專業且親切的繁體中文，詳細向我說明診斷結論、故障根本原因與具體修復處置步驟！"
            else:
                current_message = f"[後續提問] {masked_prompt}"
            yield {"type": "status", "content": "收到提問，正在為您分析並產生診斷回答..."}

        iteration = 0
        has_final_report = False

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

            # 如果 AI 本次回傳了文字訊息
            text_parts = [part.text for part in model_content.parts if part.text]
            if text_parts and not function_calls:
                raw_report = "\n".join(text_parts)
                final_report = self.masking_engine.unmask_text(raw_report)
                yield {"type": "final_report", "content": final_report}
                has_final_report = True
                break

            # 處理工具調用
            tool_responses = []
            for call in function_calls:
                fn_name = call.name
                args = dict(call.args) if call.args else {}

                if fn_name == "execute_firewall_command":
                    raw_cmd = args.get("command", "").strip()
                    actual_cmd = self.masking_engine.unmask_text(raw_cmd)
                    reason = self.masking_engine.unmask_text(args.get("reason", "排查設備狀態"))

                    yield {
                        "type": "tool_call",
                        "command": actual_cmd,
                        "reason": reason,
                        "iteration": iteration,
                    }

                    raw_output = self.connector.run_command(actual_cmd)
                    masked_output = self.masking_engine.mask_text(raw_output)

                    if len(masked_output) > 4000:
                        clipped_output = masked_output[:2500] + "\n\n...[日誌過長，截斷]...\n\n" + masked_output[-1200:]
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

        # 關鍵保險：如果達到了迭代上限，強制讓 AI 進行收尾總結，絕對不留白！
        if not has_final_report:
            yield {"type": "status", "content": "已完成設備狀態數據蒐集，正在綜合推論產生最終診斷報告..."}
            force_summary_prompt = "你已經執行了足夠的診斷指令。現在請不要再調用任何工具，請立即根據剛才所收集到的所有設備輸出，給出完整、專業的繁體中文診斷結論報告，說明根本原因與修復建議。"
            try:
                forced_resp = self._send_message_with_retry(force_summary_prompt)
                cand = forced_resp.candidates[0]
                texts = [p.text for p in cand.content.parts if p.text]
                if texts:
                    final_report = self.masking_engine.unmask_text("\n".join(texts))
                    yield {"type": "final_report", "content": final_report}
                else:
                    yield {"type": "final_report", "content": "已完成排查，請參考上方各輪次抓取之設備日誌。"}
            except Exception as e:
                yield {"type": "final_report", "content": f"排查完成，但在生成總結文字時發生錯誤: {str(e)}。"}
