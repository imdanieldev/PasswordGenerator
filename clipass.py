import os
import sys
import sqlite3
import time
import string
import secrets
import base64
from datetime import datetime
from getpass import getpass
from datetime import datetime, timezone
from colorama import Fore, Back, Style, init as colorama_init
import pyperclip

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

colorama_init(autoreset=True)

APP_DIR = os.path.abspath(".")
DB_PATH = os.path.join(APP_DIR, "passwords.db")
CONFIG_PATH = os.path.join(APP_DIR, "config.sec")
DEFAULT_ITERATIONS = 300_000  

def _derive_key(master_password: str, salt: bytes, iterations: int) -> bytes:
    if not isinstance(master_password, str) or master_password == "":
        raise ValueError("Master password is required.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))
    return key

def _new_salt() -> bytes:
    return secrets.token_bytes(16)

def _load_or_init_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "rb") as f:
            data = f.read()
        try:
            salt, iter_bytes = data[:16], data[16:20]
            iterations = int.from_bytes(iter_bytes, "big")
            if iterations < 100_000:
                iterations = DEFAULT_ITERATIONS
            return salt, iterations
        except Exception:
            print(Fore.RED + "Config file corrupted. Delete config.sec to reinitialize.")
            sys.exit(1)
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

def generate_password(
    length: int = 16,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    symbols: str = string.punctuation
) -> str:
    pools = []
    if use_lower: pools.append(string.ascii_lowercase)
    if use_upper: pools.append(string.ascii_uppercase)
    if use_digits: pools.append(string.digits)
    if use_symbols and symbols: pools.append(symbols)

    if not pools:
        raise ValueError("At least one character set must be enabled.")

    password_chars = []
    for pool in pools:
        password_chars.append(secrets.choice(pool))

    all_chars = "".join(pools)
    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars[:length])


def encrypt_text(cipher: Fernet, plaintext: str) -> bytes:
    return cipher.encrypt(plaintext.encode("utf-8"))

def decrypt_text(cipher: Fernet, ciphertext: bytes) -> str:
    return cipher.decrypt(ciphertext).decode("utf-8")


def action_create(conn, cipher):
    try:
        platform = input(Fore.CYAN + "Platform: ").strip()
        if not platform:
            print(Fore.RED + "Platform cannot be empty.")
            return

        username = input(Fore.CYAN + "Username (optional): ").strip()
        note = input(Fore.CYAN + "Note (optional): ").strip()

        try:
            length = int(input(Fore.CYAN + "Password length (>=8 recommended): ").strip())
        except ValueError:
            print(Fore.RED + "Length must be a number.")
            return
        if length < 4:
            print(Fore.RED + "Length too short.")
            return

        use_lower = input(Fore.CYAN + "Include lowercase (Y/N): ").strip().lower() != "n"
        use_upper = input(Fore.CYAN + "Include uppercase (Y/N): ").strip().lower() != "n"
        use_digits = input(Fore.CYAN + "Include digits (Y/N): ").strip().lower() != "n"
        use_symbols = input(Fore.CYAN + "Include symbols (Y/N): ").strip().lower() != "n"

        password = generate_password(
            length=length,
            use_lower=use_lower,
            use_upper=use_upper,
            use_digits=use_digits,
            use_symbols=use_symbols,
        )

        print(Fore.GREEN + "Generated password:")
        print(Back.BLACK + Fore.GREEN + password)
        do_copy = input(Fore.CYAN + "Copy to clipboard (Y/N): ").strip().lower()
        if do_copy == "y":
            try:
                pyperclip.copy(password)
                print(Fore.GREEN + "Copied to clipboard.")
            except Exception as e:
                print(Fore.YELLOW + f"Clipboard not available: {e}")

        entry_text = f"platform={platform}\nusername={username}\nnote={note}\npassword={password}"
        enc = encrypt_text(cipher, entry_text)
        conn.execute(
            "INSERT INTO entries(platform, username, note, password_enc, created_at) VALUES(?,?,?,?,?)",
            (platform, username, note, enc, datetime.now(timezone.utc).isoformat(timespec="seconds"))
        )
        conn.commit()
        print(Fore.GREEN + "Saved securely.")
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nCancelled.")

def _format_entry_plaintext(plaintext: str) -> dict:
    info = {"platform": "", "username": "", "note": "", "password": ""}
    for line in plaintext.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k in info:
                info[k] = v
    return info

def action_list(conn, cipher):
    rows = conn.execute("SELECT id, platform, username, note, password_enc, created_at FROM entries ORDER BY created_at DESC").fetchall()
    if not rows:
        print(Fore.YELLOW + "No entries found.")
        return
    for r in rows:
        id_, platform, username, note, enc, created_at = r
        try:
            plain = decrypt_text(cipher, enc)
            info = _format_entry_plaintext(plain)
            print(Back.WHITE + Fore.BLACK + f"ID: {id_} | {platform} | {created_at}")
            print(Style.RESET_ALL + f"Username: {info.get('username','')}")
            print(f"Note: {info.get('note','')}")
            print(Fore.GREEN + f"Password: {info.get('password','')}")
            print("-" * 40)
        except Exception:
            print(Fore.RED + f"ID {id_}: corrupted or wrong master password?")
            print("-" * 40)

def action_search(conn, cipher):
    term = input(Fore.CYAN + "Search platform contains: ").strip()
    if not term:
        print(Fore.YELLOW + "Search term is empty.")
        return
    rows = conn.execute(
        "SELECT id, platform, username, note, password_enc, created_at FROM entries WHERE platform LIKE ? ORDER BY created_at DESC",
        (f"%{term}%",)
    ).fetchall()
    if not rows:
        print(Fore.YELLOW + "No matches.")
        return
    for r in rows:
        id_, platform, username, note, enc, created_at = r
        try:
            plain = decrypt_text(cipher, enc)
            info = _format_entry_plaintext(plain)
            print(Back.WHITE + Fore.BLACK + f"ID: {id_} | {platform} | {created_at}")
            print(Style.RESET_ALL + f"Username: {info.get('username','')}")
            print(f"Note: {info.get('note','')}")
            print(Fore.GREEN + f"Password: {info.get('password','')}")
            print("-" * 40)
        except Exception:
            print(Fore.RED + f"ID {id_}: corrupted or wrong master password?")
            print("-" * 40)

def action_copy(conn, cipher):
    try:
        id_str = input(Fore.CYAN + "Entry ID to copy password: ").strip()
        entry_id = int(id_str)
    except ValueError:
        print(Fore.RED + "ID must be a number.")
        return
    row = conn.execute("SELECT password_enc FROM entries WHERE id = ?", (entry_id,)).fetchone()
    if not row:
        print(Fore.YELLOW + "Entry not found.")
        return
    try:
        plain = decrypt_text(cipher, row[0])
        info = _format_entry_plaintext(plain)
        pyperclip.copy(info.get("password", ""))
        print(Fore.GREEN + "Password copied to clipboard.")
    except Exception as e:
        print(Fore.RED + f"Failed to decrypt/copy: {e}")

def action_delete(conn, cipher):
    try:
        id_str = input(Fore.CYAN + "Entry ID to delete: ").strip()
        entry_id = int(id_str)
    except ValueError:
        print(Fore.RED + "ID must be a number.")
        return
    row = conn.execute("SELECT id FROM entries WHERE id = ?", (entry_id,)).fetchone()
    if not row:
        print(Fore.YELLOW + "Entry not found.")
        return
    confirm = input(Fore.RED + f"Delete ID {entry_id}? (Y/N): ").strip().lower()
    if confirm == "y":
        conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        conn.commit()
        print(Fore.GREEN + "Deleted.")
    else:
        print(Fore.YELLOW + "Cancelled.")

def action_change_master(conn):
    print(Fore.YELLOW + "Changing master password will rewrap your encryption key.")
    old_master = getpass("Current master password: ")
    try:
        old_cipher = init_cipher(old_master)
    except Exception:
        print(Fore.RED + "Invalid current master password.")
        return

    row = conn.execute("SELECT password_enc FROM entries LIMIT 1").fetchone()
    if row:
        try:
            _ = decrypt_text(old_cipher, row[0])
        except Exception:
            print(Fore.RED + "Current master password is incorrect.")
            return

    new_master = getpass("New master password: ")
    confirm_master = getpass("Repeat new master password: ")
    if new_master != confirm_master or new_master == "":
        print(Fore.RED + "Master passwords do not match or empty.")
        return

    new_salt = _new_salt()
    iterations = DEFAULT_ITERATIONS
    with open(CONFIG_PATH, "wb") as f:
        f.write(new_salt + iterations.to_bytes(4, "big"))

    new_cipher = init_cipher(new_master)

    rows = conn.execute("SELECT id, password_enc FROM entries").fetchall()
    for id_, enc in rows:
        plain = decrypt_text(old_cipher, enc)  
        new_enc = encrypt_text(new_cipher, plain)
        conn.execute("UPDATE entries SET password_enc = ? WHERE id = ?", (new_enc, id_))
    conn.commit()
    print(Fore.GREEN + "Master password changed and entries re-encrypted.")

def print_menu():
    print(Back.BLUE + Fore.WHITE + "Password Manager")
    print(Style.RESET_ALL + "Choose an option:")
    print("1) Create new entry")
    print("2) List all entries")
    print("3) Search by platform")
    print("4) Copy password by ID")
    print("5) Delete entry by ID")
    print("6) Change master password")
    print("0) Exit")

def main():
    conn = _connect_db()
    _init_db(conn)

    print(Fore.MAGENTA + "Enter your master password. It protects all stored data.")
    master = getpass("Master password: ")
    try:
        cipher = init_cipher(master)
    except Exception as e:
        print(Fore.RED + f"Failed to initialize cipher: {e}")
        sys.exit(1)
    while True:
        print_menu()
        choice = input(Fore.CYAN + "Option: ").strip()
        if choice == "1":
            action_create(conn, cipher)
        elif choice == "2":
            action_list(conn, cipher)
        elif choice == "3":
            action_search(conn, cipher)
        elif choice == "4":
            action_copy(conn, cipher)
        elif choice == "5":
            action_delete(conn, cipher)
        elif choice == "6":
            action_change_master(conn)
            master = getpass("Re-enter master to continue: ")
            try:
                cipher = init_cipher(master)
            except Exception as e:
                print(Fore.RED + f"Failed to reinitialize cipher: {e}")
                break
        elif choice == "0":
            print(Fore.GREEN + "Goodbye.")
            break
        else:
            print(Fore.YELLOW + "Invalid choice.")

        time.sleep(0.2)

    conn.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nExit.")