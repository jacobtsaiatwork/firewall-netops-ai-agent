"""
Device Vault Manager.
Stores saved firewall profiles locally in a JSON file for quick access.
"""

import json
import os
from typing import List, Dict, Optional

VAULT_FILE = os.path.join(os.path.dirname(__file__), "device_vault.json")

class DeviceVaultManager:
    @staticmethod
    def load_devices() -> List[Dict]:
        if not os.path.exists(VAULT_FILE):
            return []
        try:
            with open(VAULT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    @staticmethod
    def save_device(device: Dict) -> List[Dict]:
        devices = DeviceVaultManager.load_devices()
        # 依 host 與 port 更新或新增
        existing_idx = None
        for i, d in enumerate(devices):
            if d.get("host") == device.get("host") and d.get("port") == device.get("port"):
                existing_idx = i
                break

        if existing_idx is not None:
            devices[existing_idx] = device
        else:
            devices.append(device)

        with open(VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(devices, f, ensure_ascii=False, indent=2)
        return devices

    @staticmethod
    def delete_device(host: str, port: int = 22) -> List[Dict]:
        devices = DeviceVaultManager.load_devices()
        devices = [d for d in devices if not (d.get("host") == host and d.get("port") == port)]
        with open(VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(devices, f, ensure_ascii=False, indent=2)
        return devices
