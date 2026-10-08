"""
Firewall AI Troubleshooter - Command Line Interface (CLI)
"""

import sys
import os
import getpass
from firewall_connector import FirewallConnector
from firewall_agent import FirewallAgent

def print_banner():
    print("=" * 65)
    print("       🛡️  萬用防火牆 AI 自動排錯助理 (NetOps Copilot) - CLI")
    print("       支援設備：Palo Alto (PAN-OS) / Fortinet (FortiOS)")
    print("=" * 65)

def main():
    print_banner()

    # 1. 取得 API KEY
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        api_key = input("請輸入 Google Gemini API Key: ").strip()
        if not api_key:
            print("❌ 錯誤：未提供 API Key，程式結束。")
            sys.exit(1)

    # 2. 設備連線設定
    print("\n【請輸入目標防火牆連線資訊】")
    device_type_input = input("設備類型 [1: Palo Alto, 2: Fortinet] (預設 1): ").strip() or "1"
    device_type = "paloalto_panos" if device_type_input == "1" else "fortinet"

    host = input("防火牆 IP 位址: ").strip()
    if not host:
        print("❌ 錯誤：IP 不能為空。")
        sys.exit(1)

    port_input = input("SSH Port (預設 22): ").strip() or "22"
    port = int(port_input)

    username = input("管理員帳號: ").strip()
    password = getpass.getpass("管理員密碼: ").strip()

    print(f"\n⏳ 正在連線至設備 ({host}:{port})...")
    connector = FirewallConnector(
        device_type=device_type,
        host=host,
        username=username,
        password=password,
        port=port
    )

    try:
        connector.connect()
        print("✅ 設備 SSH 連線成功！")
    except Exception as e:
        print(f"❌ 設備連線失敗: {e}")
        retry = input("是否仍要以離線/模擬模式繼續測試 Agent？(y/N): ").strip().lower()
        if retry != "y":
            sys.exit(1)

    try:
        agent = FirewallAgent(connector=connector, api_key=api_key)
        print("\n💡 您現在可以隨意輸入任何排錯問題！例如：")
        print("   - '為什麼 ethernet1/1 在下午 14:00 會 down？'")
        print("   - '為什麼 192.168.1.1 連不到 192.168.2.2？'")
        print("   - '目前防火牆 CPU 使用率是否正常？哪些行程佔用最多？'")
        print("   (輸入 'exit' 或 'quit' 結束)\n")

        while True:
            prompt = input("\n🔍 請輸入排查 Prompt > ").strip()
            if not prompt:
                continue
            if prompt.lower() in ("exit", "quit"):
                print("感謝使用，再見！")
                break

            print("\n" + "-" * 50)
            print("🚀 AI Agent 開始深入排查中...")
            print("-" * 50)

            for step in agent.run_investigation(prompt):
                step_type = step.get("type")
                if step_type == "status":
                    print(f"ℹ️  {step['content']}")
                elif step_type == "tool_call":
                    print(f"\n🛠️  [第 {step.get('iteration')} 輪排查 - 執行指令]")
                    print(f"   理由: {step.get('reason')}")
                    print(f"   指令: ➜ {step.get('command')}")
                elif step_type == "tool_result":
                    print("   [設備輸出預覽]:")
                    lines = step.get('output_preview', '').split('\n')
                    for l in lines[:5]:
                        print(f"     | {l}")
                    if len(lines) > 5:
                        print(f"     | ... (共 {len(lines)} 行)")
                elif step_type == "final_report":
                    print("\n" + "=" * 50)
                    print("📋 【AI 診斷報告】")
                    print("=" * 50)
                    print(step.get('content'))
                    print("=" * 50)
                elif step_type == "error":
                    print(f"\n❌ 排查發生錯誤: {step.get('content')}")

    finally:
        connector.close()

if __name__ == "__main__":
    main()
