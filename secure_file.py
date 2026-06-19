#!/usr/bin/env python3
"""
SecureFile - Password-Based File Encryption/Decryption Tool
==============================================================
Encrypts and decrypts arbitrary files (images, PDFs, documents, etc.)
using a password you choose. Built on the official `cryptography`
library.

Crypto design:
  - Password -> 256-bit key via PBKDF2HMAC-SHA256 (480,000 iterations)
  - A random 16-byte salt is generated per file and stored as a header
    in the output file, so only the password needs to be remembered.
  - Actual encryption uses Fernet (AES-128-CBC + HMAC-SHA256), which
    authenticates the data: wrong passwords or corrupted/tampered
    files are detected and rejected rather than producing garbage.

Run with:  python3 secure_file.py
Requires:  pip install cryptography
"""

import os
import base64
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
ITERATIONS = 480_000  # OWASP 2023 recommendation for PBKDF2-SHA256


def derive_key(password: str, salt: bytes) -> bytes:
    """Turn a human password + salt into a Fernet-compatible 256-bit key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    with open(output_path, "wb") as f:
        f.write(salt)          # header: salt used for this file
        f.write(encrypted)     # body: ciphertext + auth tag


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        content = f.read()

    if len(content) < SALT_SIZE:
        raise ValueError("File is too small to be a valid encrypted file.")

    salt = content[:SALT_SIZE]
    encrypted = content[SALT_SIZE:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        raise ValueError("Incorrect password, or the file is corrupted/not a valid encrypted file.")

    with open(output_path, "wb") as f:
        f.write(decrypted)


class SecureFileApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("SecureFile — Password File Encryption")
        root.geometry("540x340")
        root.resizable(False, False)

        self.filepath = tk.StringVar()
        self.password = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Ready.")

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 12, "pady": 6}

        frame = ttk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="File to encrypt / decrypt:").grid(
            row=0, column=0, columnspan=3, sticky="w", **pad)

        entry_file = ttk.Entry(frame, textvariable=self.filepath, width=50)
        entry_file.grid(row=1, column=0, columnspan=2, sticky="we", padx=12)
        ttk.Button(frame, text="Browse…", command=self.browse_file).grid(
            row=1, column=2, padx=6)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, columnspan=3, sticky="w", **pad)

        self.entry_pw = ttk.Entry(frame, textvariable=self.password, show="*", width=50)
        self.entry_pw.grid(row=3, column=0, columnspan=2, sticky="we", padx=12)
        ttk.Checkbutton(frame, text="Show", variable=self.show_password,
                         command=self.toggle_password).grid(row=3, column=2, padx=6)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=22)
        ttk.Button(btn_frame, text="🔒 Encrypt File", width=20,
                   command=self.start_encrypt).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="🔓 Decrypt File", width=20,
                   command=self.start_decrypt).pack(side="left", padx=10)

        self.progress = ttk.Progressbar(frame, mode="indeterminate")
        self.progress.grid(row=5, column=0, columnspan=3, sticky="we", padx=12, pady=8)

        ttk.Label(frame, textvariable=self.status, foreground="#555").grid(
            row=6, column=0, columnspan=3, sticky="w", padx=12)

        ttk.Label(
            frame,
            text=("Encrypted output is saved alongside the original with a .enc extension.\n"
                  "There is no password recovery — if you forget it, the file cannot be opened."),
            foreground="#888", justify="left",
        ).grid(row=7, column=0, columnspan=3, sticky="w", padx=12, pady=(12, 0))

    def toggle_password(self):
        self.entry_pw.config(show="" if self.show_password.get() else "*")

    def browse_file(self):
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.filepath.set(path)

    def _validate(self):
        path = self.filepath.get().strip()
        pw = self.password.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid file.")
            return None, None
        if not pw:
            messagebox.showerror("Error", "Please enter a password.")
            return None, None
        return path, pw

    def start_encrypt(self):
        path, pw = self._validate()
        if path is None:
            return
        output = path + ".enc"
        self._run_async(encrypt_file, path, output, pw,
                         "Encrypting…", f"File encrypted successfully:\n{output}")

    def start_decrypt(self):
        path, pw = self._validate()
        if path is None:
            return
        output = path[:-4] if path.endswith(".enc") else path + ".dec"
        self._run_async(decrypt_file, path, output, pw,
                         "Decrypting…", f"File decrypted successfully:\n{output}")

    def _run_async(self, func, path, output, pw, busy_text, success_text):
        self.status.set(busy_text)
        self.progress.start(10)

        def task():
            try:
                func(path, output, pw)
                self.root.after(0, lambda: self._finish(True, success_text))
            except Exception as e:
                self.root.after(0, lambda: self._finish(False, str(e)))

        threading.Thread(target=task, daemon=True).start()

    def _finish(self, success, message):
        self.progress.stop()
        self.status.set("Ready.")
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    SecureFileApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()