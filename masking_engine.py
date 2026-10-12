"""
Data Masking Engine for Firewall NetOps AI.
Anonymizes sensitive customer data (IPs, Hostnames) before sending to LLM,
and decodes back on local client display.
"""

import re
from typing import Tuple, Dict

class DataMaskingEngine:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.ip_map: Dict[str, str] = {}
        self.reverse_ip_map: Dict[str, str] = {}
        self.ip_counter = 1

    def reset(self):
        self.ip_map.clear()
        self.reverse_ip_map.clear()
        self.ip_counter = 1

    def mask_text(self, text: str) -> str:
        """將敏感 IP 替換成代號 [IP_1], [IP_2]..."""
        if not self.enabled or not text:
            return text

        # 正則表達式匹配 IPv4 位址
        ip_pattern = r"\b(?!(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.0|255\.255\.255\.255)\b)(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

        def replace_ip(match):
            ip = match.group(0)
            if ip not in self.ip_map:
                mask_tag = f"[NET_IP_{self.ip_counter}]"
                self.ip_counter += 1
                self.ip_map[ip] = mask_tag
                self.reverse_ip_map[mask_tag] = ip
            return self.ip_map[ip]

        masked_text = re.sub(ip_pattern, replace_ip, text)
        return masked_text

    def unmask_text(self, text: str) -> str:
        """將 AI 診斷報告中的代號還原成真實 IP"""
        if not self.enabled or not text:
            return text

        unmasked_text = text
        for mask_tag, original_ip in self.reverse_ip_map.items():
            unmasked_text = unmasked_text.replace(mask_tag, original_ip)
        return unmasked_text
