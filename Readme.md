# 🔐 Password Manager (Python + SQLite + Encryption)

A secure command-line password manager built with Python.  
It generates strong random passwords, encrypts them with a master password, and stores them safely in SQLite.

---

## ✨ Features
- **Strong password generation** with customizable character sets
- **Secure storage** using `cryptography.Fernet` with PBKDF2HMAC key derivation
- **SQLite database** for lightweight and reliable storage
- **Master Password protection** (all entries encrypted with your key)
- **Clipboard integration** via `pyperclip`
- **Interactive CLI menu** with colorized output (`colorama`)
- **Search, list, copy, and delete entries**
- **Change Master Password** and re-encrypt all data

---

## 📦 Installation

### Clone or download the project
```bash
git clone https://github.com/imdanieldev/PasswordGenerator.git
cd password-manager
pip install cryptography colorama pyperclip
python main.py
```
## 🖥️ Usage
**Enter your Master Password (used to derive the encryption key).**

### Choose an option from the menu:

- **Create a new entry**

- **List all entries**

- **Search by platform**

- **Copy password by ID**

- **Delete entry by ID**

- **Change Master Password**

- **Exit**