import re
import threading
from typing import Optional
import paramiko
from paramiko.rsakey import RSAKey
from netmiko import ConnectHandler

_orig_verify_ssh_sig = RSAKey.verify_ssh_sig

def patched_verify_ssh_sig(self, data, msg):
    raw_bytes = msg.asbytes()
    try:
        if _orig_verify_ssh_sig(self, data, paramiko.message.Message(raw_bytes)):
            return True
    except Exception:
        pass

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
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        for h in (hashes.SHA256(), hashes.SHA512(), hashes.SHA1()):
            try:
                msg_cur = paramiko.message.Message(raw_bytes)
                _ = msg_cur.get_text()
                sig = msg_cur.get_binary()
                self.key.verify(sig, data, padding.PKCS1v15(), h)
                return True
            except Exception:
                continue
        return False

RSAKey.verify_ssh_sig = patched_verify_ssh_sig

if hasattr(paramiko.Transport, "_key_info"):
    if "ssh-rsa" not in paramiko.Transport._key_info:
        paramiko.Transport._key_info["ssh-rsa"] = RSAKey
    if "ssh-rsa-cert-v01@openssh.com" not in paramiko.Transport._key_info:
        paramiko.Transport._key_info["ssh-rsa-cert-v01@openssh.com"] = RSAKey

if hasattr(paramiko.Transport, "_preferred_keys"):
    keys = list(paramiko.Transport._preferred_keys)
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
        read_timeout: int = 35,
    ):
        self.raw_type = device_type.lower()
        self.device_type = "paloalto_panos" if "pa" in self.raw_type else "fortinet"
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.secret = secret or ""
        self.timeout = timeout
        self.read_timeout = read_timeout
        self.connection = None
        self._lock = threading.Lock()  # 線程安全鎖，避免指令並發穿插

    def connect(self):
        with self._lock:
            try:
                device_params = {
                    "device_type": self.device_type,
                    "host": self.host,
                    "username": self.username,
                    "password": self.password,
                    "port": self.port,
                    "secret": self.secret,
                    "timeout": self.timeout,
                    "banner_timeout": self.timeout,
                    "auth_timeout": self.timeout,
                    "conn_timeout": self.timeout,
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

        with self._lock:
            if not self.connection:
                self.connect()

            try:
                output = self.connection.send_command(command, read_timeout=self.read_timeout)
                return output
            except Exception as e:
                try:
                    self.connect()
                    output = self.connection.send_command(command, read_timeout=self.read_timeout)
                    return output
                except Exception as retry_err:
                    return f"[執行失敗] 指令 '{command}' 錯誤: {str(retry_err)}"

    def close(self):
        with self._lock:
            if self.connection:
                try:
                    self.connection.disconnect()
                except Exception:
                    pass
                self.connection = None
