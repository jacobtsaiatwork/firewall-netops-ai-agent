"""
Secure Device Vault Manager with Fernet symmetric encryption.
Protects stored passwords from plain-text exposure in device_vault.json.
"""

import os
import json
import base64
from typing import List, Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = os.path.join(os.path.dirname(__file__), "device_vault.json")
KEY_FILE = os.path.join(os.path.dirname(__file__), ".vault.key")

def _get_or_create_cipher() -> Fernet:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return Fernet(key)

class DeviceVaultManager:
    @staticmethod
    def load_devices() -> List[Dict]:
        if not os.path.exists(VAULT_FILE):
            return []
        try:
            cipher = _get_or_create_cipher()
            with open(VAULT_FILE, "r", encoding="utf-8") as f:
                devices = json.load(f)

            # 解密密碼
            for d in devices:
                enc_pwd = d.get("password_enc")
                if enc_pwd:
                    try:
                        d["password"] = cipher.decrypt(enc_pwd.encode("utf-8")).decode("utf-8")
                    except Exception:
                        d["password"] = ""
                elif "password" in d:
                    pass
            return devices
        except Exception:
            return []

    @staticmethod
    def save_device(device: Dict) -> List[Dict]:
        devices = DeviceVaultManager.load_devices()
        cipher = _get_or_create_cipher()

        # 加密密碼，移除明文密碼欄位
        pwd = device.pop("password", "")
        if pwd:
            device["password_enc"] = cipher.encrypt(pwd.encode("utf-8")).decode("utf-8")
        else:
            device["password_enc"] = ""

        # 比對 host & port 更新或新增
        existing_idx = None
        for i, d in enumerate(devices):
            if d.get("host") == device.get("host") and d.get("port") == device.get("port"):
                existing_idx = i
                break

        if existing_idx is not None:
            devices[existing_idx] = device
        else:
            devices.append(device)

        # 儲存至檔案（確保檔案中只有加密後的字串）
        storage_devices = []
        for d in devices:
            d_copy = dict(d)
            d_copy.pop("password", None)
            storage_devices.append(d_copy)

        with open(VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(storage_devices, f, ensure_ascii=False, indent=2)

        return DeviceVaultManager.load_devices()

    @staticmethod
    def delete_device(host: str, port: int = 22) -> List[Dict]:
        devices = DeviceVaultManager.load_devices()
        devices = [d for d in devices if not (d.get("host") == host and d.get("port") == port)]

        cipher = _get_or_create_cipher()
        storage_devices = []
        for d in devices:
            d_copy = dict(d)
            pwd = d_copy.pop("password", "")
            if pwd:
                d_copy["password_enc"] = cipher.encrypt(pwd.encode("utf-8")).decode("utf-8")
            storage_devices.append(d_copy)

        with open(VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(storage_devices, f, ensure_ascii=False, indent=2)

        return DeviceVaultManager.load_devices()
