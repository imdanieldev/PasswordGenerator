import os
import sqlite3
import string
import secrets
import base64
import pyperclip
import customtkinter as ctk
from datetime import datetime, timezone
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

APP_DIR = os.path.abspath(".")
DB_PATH = os.path.join(APP_DIR, "passwords.db")
CONFIG_PATH = os.path.join(APP_DIR, "config.sec")
DEFAULT_ITERATIONS = 300_000

def _derive_key(master_password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))

def _new_salt() -> bytes:
    return secrets.token_bytes(16)

def _load_or_init_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "rb") as f:
            data = f.read()
        salt, iter_bytes = data[:16], data[16:20]
        iterations = int.from_bytes(iter_bytes, "big")
        if iterations < 100_000:
            iterations = DEFAULT_ITERATIONS
        return salt, iterations
    else:
        salt = _new_salt()
        iterations = DEFAULT_ITERATIONS
        with open(CONFIG_PATH, "wb") as f:
            f.write(salt + iterations.to_bytes(4, "big"))
        return salt, iterations

def init_cipher(master_password: str) -> Fernet:
    salt, iterations = _load_or_init_config()
    key = _derive_key(master_password, salt, iterations)
    return Fernet(key)

def _connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def _init_db(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT NOT NULL,
            username TEXT,
            note TEXT,
            password_enc BLOB NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    conn.commit()

def generate_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
    pools = []
    if use_lower: pools.append(string.ascii_lowercase)
    if use_upper: pools.append(string.ascii_uppercase)
    if use_digits: pools.append(string.digits)
    if use_symbols: pools.append(string.punctuation)
    if not pools:
        raise ValueError("No character sets selected")
    password_chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars[:length])

def encrypt_text(cipher: Fernet, plaintext: str) -> bytes:
    return cipher.encrypt(plaintext.encode("utf-8"))

def decrypt_text(cipher: Fernet, ciphertext: bytes) -> str:
    return cipher.decrypt(ciphertext).decode("utf-8")

def parse_plaintext(plaintext: str) -> dict:
    info = {"platform": "", "username": "", "note": "", "password": ""}
    for line in plaintext.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip().lower()] = v.strip()
    return info

class PasswordManagerGUI(ctk.CTk):
    def __init__(self, cipher, conn):
        super().__init__()
        self.cipher = cipher
        self.conn = conn
        self.title("Password Manager")
        self.geometry("800x600")

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(expand=True, fill="both")

        self.tab_create = self.tabview.add("Create")
        self.tab_list = self.tabview.add("List")
        self.tab_search = self.tabview.add("Search")

        self.platform_entry = self._add_entry(self.tab_create, "Platform")
        self.username_entry = self._add_entry(self.tab_create, "Username")
        self.note_entry = self._add_entry(self.tab_create, "Note")
        self.length_entry = self._add_entry(self.tab_create, "Password Length", default="12")
        ctk.CTkButton(self.tab_create, text="Generate & Save", command=self.create_entry).pack(pady=10)

        self.listbox = ctk.CTkTextbox(self.tab_list, width=700, height=400)
        self.listbox.pack(pady=10)
        ctk.CTkButton(self.tab_list, text="Refresh", command=self.list_entries).pack(pady=5)

        self.search_entry = self._add_entry(self.tab_search, "Search Platform")
        ctk.CTkButton(self.tab_search, text="Search", command=self.search_entries).pack(pady=5)
        self.searchbox = ctk.CTkTextbox(self.tab_search, width=700, height=400)
        self.searchbox.pack(pady=10)

    def _add_entry(self, parent, label, default=""):
        ctk.CTkLabel(parent, text=label).pack()
        entry = ctk.CTkEntry(parent)
        entry.insert(0, default)
        entry.pack()
        return entry

    def create_entry(self):
        platform = self.platform_entry.get().strip()
        username = self.username_entry.get().strip()
        note = self.note_entry.get().strip()
        try:
            length = int(self.length_entry.get())
        except ValueError:
            messagebox.showerror("Error","Length must be a number")
            return
        password = generate_password(length=length)
        entry_text = f"platform={platform}\nusername={username}\nnote={note}\npassword={password}"
        enc = encrypt_text(self.cipher, entry_text)
        self.conn.execute("INSERT INTO entries(platform,username,note,password_enc,created_at) VALUES(?,?,?,?,?)",
                          (platform,username,note,enc,datetime.now(timezone.utc).isoformat(timespec="seconds")))
        self.conn.commit()
        pyperclip.copy(password)
        messagebox.showinfo("Saved", f"Password generated and copied:\n{password}")

    def list_entries(self):
        self.listbox.delete("1.0","end")
        rows = self.conn.execute("SELECT id,platform,username,note,password_enc,created_at FROM entries ORDER BY created_at DESC").fetchall()
        for id_,platform,username,note,enc,created in rows:
            try:
                plain = decrypt_text(self.cipher, enc)
                info = parse_plaintext(plain)
                self.listbox.insert("end", f"ID:{id_} | {platform} | {created}\nUser:{info['username']} Note:{info['note']}\nPassword:{info['password']}\n\n")
            except Exception:
                self.listbox.insert("end", f"ID:{id_} | {platform} | ERROR\n\n")

    def search_entries(self):
        self.searchbox.delete("1.0","end")
        term = self.search_entry.get().strip()
        rows = self.conn.execute("SELECT id,platform,username,note,password_enc,created_at FROM entries WHERE platform LIKE ? ORDER BY created_at DESC",(f"%{term}%",)).fetchall()
        for id_,platform,username,note,enc,created in rows:
            try:
                plain = decrypt_text(self.cipher, enc)
                info = parse_plaintext(plain)
                self.searchbox.insert("end", f"ID:{id_} | {platform} | {created}\nUser:{info['username']} Note:{info['note']}\nPassword:{info['password']}\n\n")
            except Exception:
                self.searchbox.insert("end", f"ID:{id_} | {platform} | ERROR\n\n")

def main_gui():
    master_password = input("Master password: ")
    cipher = init_cipher(master_password)
    conn = _connect_db()
    _init_db(conn)
    app = PasswordManagerGUI(cipher, conn)
    app.mainloop()
    conn.close()

if __name__ == "__main__":
    main_gui()