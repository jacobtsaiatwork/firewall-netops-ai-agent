import paramiko
from paramiko.rsakey import RSAKey

# 修復 RSA 簽名驗證：當設備使用 SHA-256/SHA-512 簽章但宣告為 ssh-rsa 時自動適配
_orig_verify_ssh_sig = RSAKey.verify_ssh_sig

def patched_verify_ssh_sig(self, data, msg):
    # 優先嘗試原生驗證
    try:
        # 拷貝 msg 以防讀取指針被移動
        msg_copy = paramiko.message.Message(msg.asbytes())
        if _orig_verify_ssh_sig(self, data, msg_copy):
            return True
    except Exception:
        pass

    # 若失敗，解析簽名演算法標籤 (例如 rsa-sha2-256 / rsa-sha2-512)
    try:
        msg_cur = paramiko.message.Message(msg.asbytes())
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
        return False

RSAKey.verify_ssh_sig = patched_verify_ssh_sig
