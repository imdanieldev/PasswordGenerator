# Password Generator Tool

A simple yet powerful command-line password generator written in Python. This interactive script helps you create strong, random passwords, view saved ones, copy them to the clipboard, and securely store them in a local file with associated platform names. It combines lowercase, uppercase letters, digits, and punctuation for maximum entropy and security.

Perfect for developers, security enthusiasts, or anyone needing quick, customizable passwords without relying on online tools.

## Features
- **Random Password Generation**: Generate passwords of any length using a full character set (letters, numbers, symbols).
- **Read Saved Passwords**: Load and display all previously saved passwords from a `./PASSWORDS` file in a highlighted format.
- **Clipboard Integration**: Automatically copy the generated password to your system's clipboard using `pyperclip`.
- **Persistent Storage**: Save passwords to a plaintext file (`./PASSWORDS`) with optional platform labels (e.g., "GitHub", "Email").
- **Colorful CLI Feedback**: Leverages `colorama` for intuitive output—green for passwords, red for errors, and styled reading mode.
- **Input Validation**: Handles invalid inputs gracefully (e.g., non-numeric length) with clear error messages.
- **Interactive Prompts**: Step-by-step user guidance with yes/no options and customizable inputs.
- **Cross-Platform**: Works on Windows, macOS, and Linux (as long as Python and dependencies are installed).

## Requirements
- **Python Version**: 3.6 or higher (tested on 3.12+)
- **Dependencies**:
  - `pyperclip` – For clipboard functionality.
  - `colorama` – For colored terminal output.
  - Built-in modules: `string`, `random` (no installation needed).

Install dependencies via pip:
```bash
pip install pyperclip colorama

## Usage
```bash
python main.py
