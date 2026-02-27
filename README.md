# SpiderCrypt

<p align="center">
  <img src="https://via.placeholder.com/900x250/0A0A0A/00FFAA?text=SPIDERCRYPT" alt="SpiderCrypt Banner" width="700"/>
</p>

<p align="center">
<pre>
  ____  ____  ___ ____  _____ ____   ____ ______     ______  _____ 
 / ___||  _ \|_ _|  _ \| ____|  _ \ / ___|  _ \ \   / /  _ \|_   _|
 \___ \| |_) || || | | |  _| | |_) | |   | |_) \ \ / /| |_) | | |  
  ___) |  __/ | || |_| | |___|  _ <| |___|  _ < \ V / |  __/  | |  
 |____/|_|   |___|____/|_____|_| \_\\____|_| \_\ \_/  |_|     |_|  
                                                                   
      >>> SECURITY & CRYPTOGRAPHY TOOLSET v1.1 <<<
</pre>
</p>

<div align="center">

**SpiderCrypt** — The all-in-one security & AI auditing CLI tool

[<image-card alt="Python 3.9+" src="https://img.shields.io/badge/Python-3.9%2B-blue" ></image-card>](https://www.python.org)
[<image-card alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" ></image-card>](https://opensource.org/licenses/MIT)
[<image-card alt="Version" src="https://img.shields.io/badge/version-1.1-green" ></image-card>](https://github.com/MouhamedSo1978/spidercrypt)
[<image-card alt="Stars" src="https://img.shields.io/github/stars/MouhamedSo1978/spidercrypt?style=social" ></image-card>](https://github.com/MouhamedSo1978/spidercrypt)

</div>

---

## 🌟 Overview

**SpiderCrypt** is a powerful open-source Python CLI tool designed to help developers, AI researchers, and security professionals secure their code and datasets.

It detects:
- Hardcoded secrets (API keys, JWTs, passwords)
- Prompt injections & jailbreaks
- **Data poisoning** in JSON datasets (label-flip attacks, backdoor triggers, label inconsistencies, etc.)
- PII leakage
- Insecure code patterns
- And more!

Perfect for auditing datasets before publishing them on Hugging Face, Kaggle, or GitHub.

---

## ✨ Key Features

| Command                | Description |
|------------------------|-----------|
| `detect-poison`        | Full JSON dataset analysis (backdoors, label-flip, entropy, insecure code vs label mismatch…) |
| `audit`                | Static code scan for secrets & injections |
| `firewall`             | Real-time prompt injection blocker |
| `ghost-pii`            | Automatically mask personal data (credit cards, emails…) |
| `encrypt` / `decrypt`  | AES-256-GCM file encryption/decryption |
| `gen-key`              | Generate a secure AES-256 key |
| `history`              | View audit history (stored in SQLite) |

---

## 🚀 Installation

```bash
git clone https://github.com/MouhamedSo1978/spidercrypt.git
cd spidercrypt

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt
pip install -e .
