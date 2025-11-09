import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import hashlib
import base64
import time

from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad

APP_SECRET = b"secret_key" 

# === Utilitare ===
def derive_bytes(data: bytes, label: bytes, n: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < n:
        counter_bytes = counter.to_bytes(4, "big")
        out += hashlib.sha256(data + label + counter_bytes).digest()
        counter += 1
    return out[:n]

def to_hex(b: bytes) -> str:
    return b.hex()

def to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

# === Funcții de criptare pentru fiecare algoritm ===
def encrypt_des(plaintext: bytes):
    key = derive_bytes(APP_SECRET, b"DES_KEY", 8)
    iv  = derive_bytes(APP_SECRET, b"DES_IV", 8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = pad(plaintext, DES.block_size)
    ct = cipher.encrypt(padded)
    meta = {
        "algorithm": "DES (CBC)",
        "key_len": len(key),
        "block_size": DES.block_size,
        "iv": iv,
        "key": key,
        "ciphertext": ct
    }
    return meta

def encrypt_3des(plaintext: bytes):
    raw_key = derive_bytes(APP_SECRET, b"3DES_KEY", 24)
    valid_key = DES3.adjust_key_parity(raw_key)
    iv = derive_bytes(APP_SECRET, b"3DES_IV", 8)
    cipher = DES3.new(valid_key, DES3.MODE_CBC, iv)
    padded = pad(plaintext, DES3.block_size)
    ct = cipher.encrypt(padded)
    meta = {
        "algorithm": "3DES (EDE, CBC)",
        "key_len": len(valid_key),
        "block_size": DES3.block_size,
        "iv": iv,
        "key": valid_key,
        "ciphertext": ct
    }
    return meta

def encrypt_aes(plaintext: bytes):
    key = derive_bytes(APP_SECRET, b"AES_KEY", 32)
    iv  = derive_bytes(APP_SECRET, b"AES_IV", 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    ct = cipher.encrypt(padded)
    meta = {
        "algorithm": "AES-256 (CBC)",
        "key_len": len(key),
        "block_size": AES.block_size,
        "iv": iv,
        "key": key,
        "ciphertext": ct
    }
    return meta

# === Interfata ===
class EncryptCompareApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Criptare: DES vs 3DES vs AES — Proiect")
        self.geometry("950x640")
        self.resizable(True, True)

        # Input
        top_frame = ttk.Frame(self, padding=10)
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Introdu parola (plaintext):").pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(top_frame, height=3)
        self.input_text.pack(fill=tk.X, pady=4)

        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(fill=tk.X, pady=6)
        encrypt_btn = ttk.Button(btn_frame, text="Criptează", command=self.on_encrypt)
        encrypt_btn.pack(side=tk.LEFT, padx=(0,6))
        clear_btn = ttk.Button(btn_frame, text="Curăță", command=self.on_clear)
        clear_btn.pack(side=tk.LEFT)

        # Results: 3 panels (DES, 3DES, AES)
        results_frame = ttk.Frame(self, padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True)

        self.panels = {}
        for algo in ["DES", "3DES", "AES"]:
            f = ttk.LabelFrame(results_frame, text=algo, padding=8)
            f.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=4)
            self.panels[algo] = self._make_panel(f)


    def _make_panel(self, parent):
        out = {}
        lbl_cipher_hex = ttk.Label(parent, text="Ciphertext (hex):")
        lbl_cipher_hex.pack(anchor=tk.W)
        txt_hex = scrolledtext.ScrolledText(parent, height=6)
        txt_hex.pack(fill=tk.BOTH, expand=True, pady=(0,6))
        txt_hex.configure(state="disabled")

        lbl_cipher_b64 = ttk.Label(parent, text="Ciphertext (base64):")
        lbl_cipher_b64.pack(anchor=tk.W)
        txt_b64 = ttk.Entry(parent)
        txt_b64.pack(fill=tk.X, pady=(0,6))

        meta_frame = ttk.Frame(parent)
        meta_frame.pack(fill=tk.X, pady=(4,0))
        labels = {}
        for key in ["Algoritm", "Key len (bytes)", "Block size", "IV (hex)", "Cipher len (bytes)", "Cheie (hex)", "Timp_executie"]:
            l = ttk.Label(meta_frame, text=f"{key}:")
            l.pack(anchor=tk.W)
            val = ttk.Label(meta_frame, text="", wraplength=260)
            val.pack(anchor=tk.W, pady=(0,6))
            labels[key] = val

        out['txt_hex'] = txt_hex
        out['txt_b64'] = txt_b64
        out['labels'] = labels
        return out

    def on_clear(self):
        self.input_text.delete("1.0", tk.END)
        for p in self.panels.values():
            p['txt_hex'].configure(state="normal")
            p['txt_hex'].delete("1.0", tk.END)
            p['txt_hex'].configure(state="disabled")
            p['txt_b64'].delete(0, tk.END)
            for lbl in p['labels'].values():
                lbl.config(text="")

    def on_encrypt(self):
        plaintext = self.input_text.get("1.0", tk.END).rstrip("\n")
        if plaintext == "":
            messagebox.showwarning("Input lipsă", "Te rog introdu o parolă (plaintext) înainte de a cripta.")
            return
        data = plaintext.encode()

        # DES
        t0 = time.perf_counter()
        meta_des = encrypt_des(data)
        t1 = time.perf_counter()
        # 3DES
        t2 = time.perf_counter()
        meta_3des = encrypt_3des(data)
        t3 = time.perf_counter()
        # AES
        t4 = time.perf_counter()
        meta_aes = encrypt_aes(data)
        t5 = time.perf_counter()

        # Show results
        self._show_meta("DES", meta_des, exec_time=(t1-t0))
        self._show_meta("3DES", meta_3des, exec_time=(t3-t2))
        self._show_meta("AES", meta_aes, exec_time=(t5-t4))

    def _show_meta(self, panel_key, meta, exec_time=None):
        p = self.panels[panel_key]
        # ciphertext hex
        hex_view = meta['ciphertext'].hex()
        p['txt_hex'].configure(state="normal")
        p['txt_hex'].delete("1.0", tk.END)
        p['txt_hex'].insert(tk.END, hex_view)
        p['txt_hex'].configure(state="disabled")
        # base64
        p['txt_b64'].delete(0, tk.END)
        p['txt_b64'].insert(0, base64.b64encode(meta['ciphertext']).decode())

        # labels
        labels = p['labels']
        labels["Algoritm"].config(text=meta['algorithm'])
        labels["Key len (bytes)"].config(text=str(meta['key_len']))
        labels["Block size"].config(text=str(meta['block_size']))
        labels["IV (hex)"].config(text=meta['iv'].hex())
        labels["Cipher len (bytes)"].config(text=str(len(meta['ciphertext'])))
        labels["Cheie (hex)"].config(text=meta['key'].hex())

        sec_note = ""
        if exec_time is not None:
            sec_note += f" (t_exec ≈ {exec_time*1000:.2f} ms)"
        labels["Timp_executie"].config(text=sec_note)

# === Run ===
if __name__ == "__main__":
    app = EncryptCompareApp()
    app.mainloop()
