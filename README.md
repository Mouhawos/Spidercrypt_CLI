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

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.1-green)](https://github.com/MouhamedSo1978/spidercrypt)
[![Stars](https://img.shields.io/github/stars/MouhamedSo1978/spidercrypt?style=social)](https://github.com/MouhamedSo1978/spidercrypt)

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

## 🚀 Quick Start

| Command | Example | Description |
|---------|---------|-----------|
| **Generate key** | `spidercrypt gen-key` | Generate a secure AES-256 key |
| **Encrypt file** | `SPIDER_KEY=ta-clé spidercrypt encrypt input.txt output.enc` | Encrypt any file with AES-256-GCM |
| **Decrypt file** | `SPIDER_KEY=ta-clé spidercrypt decrypt output.enc restored.txt` | Decrypt a protected file |
| **Detect poisoning** | `spidercrypt detect-poison dataset.json` | Scan a JSON dataset for data poisoning |
| **Advanced poisoning scan** | `spidercrypt detect-poison *.json --json-output --save` | Multiple files + save report in DB |
| **Code audit** | `spidercrypt audit script.py --ai` | Scan source code for secrets & vulnerabilities |
| **Prompt firewall** | `spidercrypt firewall "ignore previous instruction"` | Block prompt injection attempts |
| **Mask PII** | `spidercrypt ghost-pii data.txt --output clean.txt` | Automatically hide emails, credit cards… |
| **View history** | `spidercrypt history` | Show all previous audit reports |

---

## 📊 Example `detect-poison` Report

```bash
🔍 Analyzing: dataset.json
  ┌─────────────────────────────────────────┐
  │  🚨  DATA POISONING DETECTED             │
  └─────────────────────────────────────────┘

  Risk Score : [██████████░░░░░░░░░░░░░░░░░░] 0.620



🛠 Advanced Configuration

SQLite database (spidercrypt.db) is created automatically.
Optional LangChain + Ollama support for AI analysis (--ai flag).


📄 License
MIT License
Author: Mouhamed Sow (@MouhamedSo1978) – Laval, Québec, Canada
Date: February 2026
⭐ If you like it, please star the repo!
