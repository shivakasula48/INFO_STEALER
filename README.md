# INFO_STEALER


## 🔐 Information Extraction Tool – Ethical Cybersecurity Utility

A versatile cross-platform Python tool that demonstrates how sensitive data (browser credentials, Wi‑Fi passwords, clipboard contents, system metadata) can be accessed and processed. Includes features like encryption, compression, stealth mode, and optional exfiltration.

---

## 📌 Overview

This project serves as an **educational and ethical demonstration** of information retrieval and system profiling techniques using Python. It supports **Windows, Linux, and macOS**, and can extract:

- Browser credentials (Chrome, Firefox, Edge, Brave, Opera)
- Wi‑Fi network passwords
- Clipboard data
- Host system information including IP and MAC address

Key features include selective **encryption**, **compression**, and optional **exfiltration**, with configurable **stealth verbosity**.

---

## 🧠 Explanation (How It Works)

1. **Environment Detection**: Determines OS (Windows, Linux, macOS).
2. **Browser Key Retrieval**: Extracts Chrome‑style safe storage keys using DPAPI or JSON-based storage, depending on platform.
3. **Password Decryption**: Supports modern AES‑GCM encrypted credentials (v10/v11) or legacy DPAPI fallback.
4. **Wi‑Fi Extraction**: Pulls stored Wi‑Fi SSIDs and plaintext passwords via OS-specific commands (`netsh`, `nmcli`, `security`).
5. **Clipboard Capture**: Grabs clipboard contents using `pyperclip`.
6. **System Profiling**: Gathers system info such as OS version, hostname, local/global IP, MAC, architecture, processor.
7. **Data Handling**: Configurable encryption (AES‑GCM + PBKDF2), zlib compression, and optional remote upload.
8. **Console Output**: Stealth vs verbose logging—with colored formatting for clarity.
9. **Cleanup**: Removes temporary files before exit.

---

## 📂 Clone the Repository

```bash
git clone https://github.com/shivakasula48/INFO_STEALER
cd INFO_STEALER
```


---

## 🚀 Running the Tool

> ⚠️ **Administrative/root privileges are recommended**, especially for Wi‑Fi credential access on Windows.

```bash
python info_extract.py
```

⚙️ Configuration flags to modify inside the script (or convert to CLI flags if desired):

* `ENABLE_EXFIL`
* `EXFIL_URL`
* `ENCRYPT_DATA`
* `COMPRESS_DATA`
* `STEALTH_MODE`
* `DELAY_MIN`, `DELAY_MAX`

---

## 📦 Dependencies

The following modules are required:

* Standard library: `os`, `sys`, `shutil`, `subprocess`, `platform`, `socket`, `uuid`, `re`, `json`, `sqlite3`, `time`, `random`, `hashlib`, `zlib`, `datetime`
* External: `requests`, `pyperclip`, `Crypto` (PyCryptodome)
* Windows only: `win32crypt` (requires `pywin32`)

Install via pip:

```bash
pip install -r requirements.txt
```

---

## 🔄 Imports Used

```python
import os, sys, shutil, subprocess, platform, socket, uuid, re
import json, sqlite3, time, random, hashlib, zlib, socket
from datetime import datetime
import requests, pyperclip
import ctypes  # for Windows admin/dpapi
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
try:
    from win32crypt import CryptUnprotectData
except ImportError:
    pass
```

---

## ⚠️ Ethical Considerations

* 🧑‍💼 Intended for **educational, research, and personal testing**.
* ❌ **Do not deploy on systems without explicit permission**.
* ⚖️ Misuse may violate privacy laws and ethical standards.
* 🚫 Never use it maliciously or for unauthorized data exfiltration.

---

## 🔍 Use Cases & Limitations

* Primarily for **security demos**, **demonstrations of system exposure risks**, and educational labs.
* Chrome-based browsers support AES‑GCM; Firefox extraction is plaintext from profile files.
* Not guaranteed to work with encrypted profile databases on Linux/macOS unless permissions and keys are available.
* Exfiltration is disabled by default—be cautious if enabling.

---

## 📁 Repository Structure

```
├── info_extract.py         # Main script
├── requirements.txt        # Dependencies list
└── README.md               # Project documentation
                
```

---

## 🧑‍💻 Author



**Kasula Shiva**  
🎓 B.Tech CSE (Cybersecurity)  
🔗 GitHub: [shivakasula48](https://github.com/shivakasula48)  
📧 Email: [shivakasula10@gmail.com](mailto:shivakasula10@gmail.com)

---

## 📜 License

This project is open-source and free to use by anyone for personal or educational purposes.  
Feel free to modify, distribute, and use the code as long as proper credit is given to the original author, **Kasula Shiva**.

---

## 📣 Acknowledgements

Based on best practices and inspired by similar projects in the cybersecurity learning community. Thanks to open‑source libraries like **PyCryptodome**, **requests**, and **pyperclip** for enabling this functionality.

sider logging modules or audit-tracing for cleaner event reporting.
