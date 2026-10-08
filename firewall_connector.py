import re
from typing import Optional
import paramiko
from paramiko.rsakey import RSAKey
from netmiko import ConnectHandler

# 1. 補丁 RSA 簽名驗證 (解決 Signature verification (ssh-rsa) failed)
_orig_verify_ssh_sig = RSAKey.verify_ssh_sig

def patched_verify_ssh_sig(self, data, msg):
    raw_bytes = msg.asbytes()
    # 嘗試原生驗證
    try:
        if _orig_verify_ssh_sig(self, data, paramiko.message.Message(raw_bytes)):
            return True
    except Exception:
        pass

    # 若原生失敗，解析簽名內部實際演算法 (如 rsa-sha2-256 / rsa-sha2-512)
    try:
        msg_cur = paramiko.message.Message(raw_bytes)
        sig_type = msg_cur.get_text()
        sig = msg_cur.get_binary()

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        if sig_type == "rsa-sha2-512":
            hash_algo = hashes.SHA512()
        elif sig_type == "rsa-sha2-256":
            hash_algo = hashes.SHA256()
        elif sig_type == "ssh-rsa":
            hash_algo = hashes.SHA1()
        else:
            return False

        self.key.verify(sig, data, padding.PKCS1v15(), hash_algo)
        return True
    except Exception:
        # 若仍失敗，依序嘗試所有常見 SHA 摘要比對
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        for h in (hashes.SHA256(), hashes.SHA512(), hashes.SHA1()):
            try:
                # 重新解包 binary sig
                msg_cur = paramiko.message.Message(raw_bytes)
                _ = msg_cur.get_text()
                sig = msg_cur.get_binary()
                self.key.verify(sig, data, padding.PKCS1v15(), h)
                return True
            except Exception:
                continue
        return False

RSAKey.verify_ssh_sig = patched_verify_ssh_sig

# 2. 註冊 ssh-rsa 到 Paramiko 5.0 的 key_info
if hasattr(paramiko.Transport, "_key_info"):
    if "ssh-rsa" not in paramiko.Transport._key_info:
        paramiko.Transport._key_info["ssh-rsa"] = RSAKey
    if "ssh-rsa-cert-v01@openssh.com" not in paramiko.Transport._key_info:
        paramiko.Transport._key_info["ssh-rsa-cert-v01@openssh.com"] = RSAKey

# 優先順序調整：讓現代 rsa-sha2 優先於舊版 ssh-rsa，以符合 RFC 8332
if hasattr(paramiko.Transport, "_preferred_keys"):
    keys = list(paramiko.Transport._preferred_keys)
    # 將 rsa-sha2-256 與 rsa-sha2-512 放在最前面，ssh-rsa 放最後作為相容備用
    for k in ("rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"):
        if k in keys:
            keys.remove(k)
    keys = ["rsa-sha2-256", "rsa-sha2-512"] + keys + ["ssh-rsa"]
    paramiko.Transport._preferred_keys = tuple(keys)

DISALLOWED_PATTERNS = [
    r"\bconfig\b",
    r"\bset\b",
    r"\bunset\b",
    r"\bdelete\b",
    r"\bedit\b",
    r"\bcommit\b",
    r"\breboot\b",
    r"\brestart\b",
    r"\bformat\b",
    r"\bshutdown\b",
    r"\bexecute\s+factoryreset\b",
    r"\bexecute\s+reboot\b",
    r"\brequest\s+restart\b",
    r"\brequest\s+shutdown\b",
    r"\bclear\b",
]

ALLOWED_PREFIXES_PA = ("show", "test", "debug")
ALLOWED_PREFIXES_FG = ("get", "show", "diagnose", "diag")

class FirewallConnectionError(Exception):
    pass

class FirewallSecurityViolation(Exception):
    pass

class FirewallConnector:
    def __init__(
        self,
        device_type: str,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        secret: Optional[str] = None,
        timeout: int = 25,
    ):
        self.raw_type = device_type.lower()
        self.device_type = "paloalto_panos" if "pa" in self.raw_type else "fortinet"
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.secret = secret or ""
        self.timeout = timeout
        self.connection = None

    def connect(self):
        try:
            device_params = {
                "device_type": self.device_type,
                "host": self.host,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "secret": self.secret,
                "timeout": self.timeout,
                "banner_timeout": 25,
                "auth_timeout": 25,
                "conn_timeout": 25,
                "fast_cli": False,
            }

            self.connection = ConnectHandler(**device_params)
            
            if self.device_type == "paloalto_panos":
                try:
                    self.connection.send_command("set cli pager off")
                except Exception:
                    pass
            return True
        except Exception as e:
            raise FirewallConnectionError(f"無法連線至設備 ({self.host}): {str(e)}")

    def is_safe_command(self, command: str) -> bool:
        cmd_clean = command.strip().lower()
        if not cmd_clean:
            return False

        for pattern in DISALLOWED_PATTERNS:
            if re.search(pattern, cmd_clean):
                return False

        allowed_prefixes = ALLOWED_PREFIXES_PA if self.device_type == "paloalto_panos" else ALLOWED_PREFIXES_FG
        if not any(cmd_clean.startswith(prefix) for prefix in allowed_prefixes):
            return False

        return True

    def run_command(self, command: str) -> str:
        if not self.is_safe_command(command):
            return f"[安全防護攔截] 指令 '{command}' 被判斷為非唯讀或潛在危險指令，已拒絕執行！"

        if not self.connection:
            self.connect()

        try:
            output = self.connection.send_command(command, read_timeout=35)
            return output
        except Exception as e:
            try:
                self.connect()
                output = self.connection.send_command(command, read_timeout=35)
                return output
            except Exception as retry_err:
                return f"[執行失敗] 指令 '{command}' 錯誤: {str(retry_err)}"

    def close(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None
