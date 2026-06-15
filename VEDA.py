import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import json
import sys
import ctypes

from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import nacl.secret
    import nacl.utils
    PYNACL_AVAILABLE = True
except ImportError:
    PYNACL_AVAILABLE = False

try:
    from alkindi import KEM
    ALKINDI_AVAILABLE = True
except ImportError:
    ALKINDI_AVAILABLE = False


class SecureFileTransferApp:
    MAGIC = b"EDT1"
    ICON_FILE = "securefile.ico"

    ENCRYPTED_ALGORITHMS = [
        "Fernet",
        "AES-256-GCM",
        "ChaCha20-Poly1305",
        "XSalsa20-Poly1305",
        "RSA-Hybrid",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
    ]

    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Transfer")
        self._apply_window_icon()
        self.load_or_generate_keys()
        self._build_dispatch_tables()
        self.build_ui()

    def _resource_path(self, relative_path):
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_path, relative_path)

    def _apply_window_icon(self):
        try:
            if os.name == "nt":
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    "com.secure.file.transfer"
                )
            icon_path = self._resource_path(self.ICON_FILE)
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

    def build_ui(self):
        tk.Label(self.root, text="Select encryption algorithm:").pack(pady=10)

        self.algorithm_var = tk.StringVar(value="AES-256-GCM")
        values = self.ENCRYPTED_ALGORITHMS

        self.algorithm_select = ttk.Combobox(
            self.root,
            textvariable=self.algorithm_var,
            state="readonly",
            values=values
        )
        self.algorithm_select.pack(pady=5)
        self.algorithm_select.bind("<<ComboboxSelected>>", self.update_warning)

        self.warning_label = tk.Label(self.root, text="", fg="green")
        self.warning_label.pack(pady=5)
        self.update_warning()

        tk.Button(self.root, text="Encrypt a File", command=self.encrypt_file).pack(pady=5)
        tk.Button(self.root, text="Decrypt a File", command=self.decrypt_file).pack(pady=5)

    def _build_dispatch_tables(self):
        self.encrypt_handlers = {
            "Fernet": self.encrypt_fernet,
            "AES-256-GCM": self.encrypt_aes_gcm,
            "ChaCha20-Poly1305": self.encrypt_chacha20_poly1305,
            "XSalsa20-Poly1305": self.encrypt_xsalsa20_poly1305,
            "RSA-Hybrid": self.encrypt_rsa_hybrid,
            "ML-KEM-512": lambda data: self.encrypt_mlkem(data, "ML-KEM-512"),
            "ML-KEM-768": lambda data: self.encrypt_mlkem(data, "ML-KEM-768"),
            "ML-KEM-1024": lambda data: self.encrypt_mlkem(data, "ML-KEM-1024"),
        }

        self.decrypt_handlers = {
            "Fernet": self.decrypt_fernet,
            "AES-256-GCM": self.decrypt_aes_gcm,
            "ChaCha20-Poly1305": self.decrypt_chacha20_poly1305,
            "XSalsa20-Poly1305": self.decrypt_xsalsa20_poly1305,
            "RSA-Hybrid": self.decrypt_rsa_hybrid,
            "ML-KEM-512": lambda data: self.decrypt_mlkem(data, "ML-KEM-512"),
            "ML-KEM-768": lambda data: self.decrypt_mlkem(data, "ML-KEM-768"),
            "ML-KEM-1024": lambda data: self.decrypt_mlkem(data, "ML-KEM-1024"),
        }

    def update_warning(self, event=None):
        algo = self.algorithm_var.get()
        if algo.startswith("ML-KEM"):
            self.warning_label.config(text="✓ Post-quantum hybrid mode (ML-KEM + AES-GCM).")
        elif algo in ("XSalsa20-Poly1305", "ChaCha20-Poly1305", "AES-256-GCM", "RSA-Hybrid"):
            self.warning_label.config(text="✓ Authenticated encryption with integrity tag.")
        else:
            self.warning_label.config(text="✓ Authenticated encryption.")

    def load_or_generate_keys(self):
        def load_or_create(path, create_fn):
            if not os.path.exists(path):
                with open(path, "wb") as f:
                    f.write(create_fn())
            with open(path, "rb") as f:
                return f.read()

        self.fernet_key = load_or_create("fernet.key", Fernet.generate_key)
        self.fernet_cipher = Fernet(self.fernet_key)

        self.aes_key = load_or_create("aes.key", lambda: os.urandom(32))
        self.chacha_key = load_or_create("chacha.key", lambda: os.urandom(32))

        if not os.path.exists("rsa_private.pem"):
            private_key = rsa.generate_private_key(
                public_exponent=65537,  # Fixed: was 65532
                key_size=3072,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            with open("rsa_private.pem", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open("rsa_public.pem", "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

        with open("rsa_private.pem", "rb") as f:
            self.rsa_private = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open("rsa_public.pem", "rb") as f:
            self.rsa_public = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

        if PYNACL_AVAILABLE:
            self.xsalsa_key = load_or_create("xsalsa.key", lambda: os.urandom(32))

        self.mlkem_keys = {}
        if ALKINDI_AVAILABLE:
            for level in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
                safe_name = level.lower().replace("-", "")
                pub_path = f"{safe_name}_public.bin"
                sec_path = f"{safe_name}_secret.bin"

                if not os.path.exists(pub_path) or not os.path.exists(sec_path):
                    with KEM(level) as kem:
                        public_key, secret_key = kem.generate_keypair()
                    with open(pub_path, "wb") as f:
                        f.write(public_key)
                    with open(sec_path, "wb") as f:
                        f.write(secret_key)

                with open(pub_path, "rb") as f:
                    public_key = f.read()
                with open(sec_path, "rb") as f:
                    secret_key = f.read()

                self.mlkem_keys[level] = (public_key, secret_key)

    def _pack_header(self, version=1):
        header = json.dumps({"version": version}).encode("utf-8")
        return self.MAGIC + len(header).to_bytes(4, "big") + header

    def _pack_header_with_algo(self, algorithm, version=1):
        header = json.dumps({"version": version, "algorithm": algorithm}).encode("utf-8")
        return self.MAGIC + len(header).to_bytes(4, "big") + header

    def _unpack_header(self, raw):
        if len(raw) < len(self.MAGIC) + 4:
            raise ValueError("Invalid encrypted file header.")
        if raw[:len(self.MAGIC)] != self.MAGIC:
            raise ValueError("Invalid encrypted file format.")
        offset = len(self.MAGIC)
        header_len = int.from_bytes(raw[offset:offset + 4], "big")
        offset += 4
        if len(raw) < offset + header_len:
            raise ValueError("Invalid encrypted file header.")
        header = json.loads(raw[offset:offset + header_len].decode("utf-8"))
        if "version" not in header:
            raise ValueError("Missing version in encrypted file header.")
        return header, raw[offset + header_len:]

    def _encrypt_to_file(self, algorithm, data, save_path):
        encrypted_data = self.encrypt_handlers[algorithm](data)
        header = self._pack_header_with_algo(algorithm)

        with open(save_path, "wb") as f:
            f.write(header + encrypted_data)

    def _decrypt_from_file(self, raw):
        header, enc_data = self._unpack_header(raw)
        algorithm = header.get("algorithm")
        if algorithm is None:
            raise ValueError("Missing algorithm in encrypted file header.")
        handler = self.decrypt_handlers.get(algorithm)
        if handler is None:
            raise ValueError(f"Unknown algorithm in file: {algorithm}")
        return handler(enc_data), algorithm

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if not file_path:
            return

        algorithm = self.algorithm_var.get()

        if algorithm not in self.encrypt_handlers:
            if algorithm in self.mlkem_keys:
                pass  # Will be handled via lambda
            else:
                messagebox.showerror("Error", f"Unknown encryption algorithm: {algorithm}")
                return

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            save_path = filedialog.asksaveasfilename(
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc")]
            )
            if not save_path:
                return

            self._encrypt_to_file(algorithm, data, save_path)
            messagebox.showinfo("Success", f"{algorithm} encryption complete.\nSaved to: {save_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to decrypt",
            filetypes=[("Encrypted files", "*.enc")]
        )
        if not file_path:
            return

        try:
            with open(file_path, "rb") as f:
                raw = f.read()

            data, algorithm = self._decrypt_from_file(raw)

            save_path = filedialog.asksaveasfilename(
                defaultextension=".bin",
                filetypes=[("All files", "*.*")]
            )
            if not save_path:
                return

            with open(save_path, "wb") as f:
                f.write(data)

            messagebox.showinfo(
                "Success",
                f"{algorithm} decryption complete.\nSaved to: {save_path}"
            )

        except InvalidTag:
            messagebox.showerror("Error", "Decryption failed: authentication tag mismatch.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def encrypt_fernet(self, data):
        return self.fernet_cipher.encrypt(data)

    def decrypt_fernet(self, enc_data):
        return self.fernet_cipher.decrypt(enc_data)

    def encrypt_aes_gcm(self, data):
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.aes_key)
        return nonce + aesgcm.encrypt(nonce, data, None)

    def decrypt_aes_gcm(self, enc_data):
        if len(enc_data) < 12 + 16:
            raise ValueError("Invalid AES-GCM data: too short.")
        nonce, ct = enc_data[:12], enc_data[12:]
        aesgcm = AESGCM(self.aes_key)
        return aesgcm.decrypt(nonce, ct, None)  # Fixed: was PyCrypto

    def encrypt_chacha20_poly1305(self, data):
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(self.chacha_key)
        return nonce + cipher.encrypt(nonce, data, None)

    def decrypt_chacha20_poly1305(self, enc_data):
        if len(enc_data) < 12 + 16:
            raise ValueError("Invalid ChaCha20-Poly1305 data: too short.")
        nonce, ct = enc_data[:12], enc_data[12:]
        cipher = ChaCha20Poly1305(self.chacha_key)
        return cipher.decrypt(nonce, ct, None)

    def encrypt_xsalsa20_poly1305(self, data):
        box = nacl.secret.SecretBox(self.xsalsa_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        return box.encrypt(data, nonce)

    def decrypt_xsalsa20_poly1305(self, enc_data):
        box = nacl.secret.SecretBox(self.xsalsa_key)
        return box.decrypt(enc_data)

    def encrypt_rsa_hybrid(self, data):
        aes_key = os.urandom(32)
        nonce = os.urandom(12)
        encrypted_key = self.rsa_public.encrypt(
            aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm = AESGCM(aes_key)
        ct = aesgcm.encrypt(nonce, data, None)
        return len(encrypted_key).to_bytes(2, "big") + encrypted_key + nonce + ct

    def decrypt_rsa_hybrid(self, enc_data):
        if len(enc_data) < 2 + 12 + 16:
            raise ValueError("Invalid RSA-Hybrid data: too short.")
        key_len = int.from_bytes(enc_data[:2], "big")
        if len(enc_data) < 2 + key_len + 12 + 16:
            raise ValueError("Invalid RSA-Hybrid data: malformed.")
        encrypted_key = enc_data[2:2 + key_len]
        offset = 2 + key_len
        nonce = enc_data[offset:offset + 12]
        ct = enc_data[offset + 12:]
        aes_key = self.rsa_private.decrypt(
            encrypted_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ct, None)

    def encrypt_mlkem(self, data, level):
        public_key, _ = self.mlkem_keys[level]
        with KEM(level) as kem:
            kem_ct, shared_secret = kem.encaps(public_key)

        aes_key = self._derive_key(shared_secret, b"mlkem-aes-gcm")
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ct = aesgcm.encrypt(nonce, data, None)

        level_bytes = level.encode()
        return level_bytes + len(kem_ct).to_bytes(2, "big") + kem_ct + nonce + ct

    def decrypt_mlkem(self, enc_data, level):
        level_bytes = level.encode()
        if enc_data[:len(level_bytes)] != level_bytes:
            raise ValueError(f"Wrong ML-KEM level for this file: {level}")

        offset = len(level_bytes)
        kem_len = int.from_bytes(enc_data[offset:offset + 2], "big")
        offset += 2
        kem_ct = enc_data[offset:offset + kem_len]
        offset += kem_len
        nonce = enc_data[offset:offset + 12]
        ct = enc_data[offset + 12:]

        _, secret_key = self.mlkem_keys[level]
        with KEM(level) as kem:
            shared_secret = kem.decaps(kem_ct, secret_key)

        aes_key = self._derive_key(shared_secret, b"mlkem-aes-gcm")
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ct, None)

    def _derive_key(self, shared_secret, info):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        return hkdf.derive(shared_secret)


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileTransferApp(root)
    root.mainloop()