# 🛡️ Spidercrypt CLI — AI & Cybersecurity Security Toolkit

Spidercrypt CLI is an advanced cybersecurity tool designed to protect AI systems, ML pipelines, and applications against:

- Prompt injections
- Data poisoning
- Sensitive data leaks
- Malicious outputs
- Application vulnerabilities
- AI jailbreak attempts

It is designed for easy integration into enterprise environments.

---

## 🚀 Features

✔ Source code analysis
✔ Prompt injection detection
✔ AI firewall (Prompt Firewall)
✔ Sensitive data masking (PII)
✔ Cleanup of dangerous outputs
✔ Data poisoning detection
✔ JSON report generation

---

## 📦 Installation

### Prerequisites

- Python 3.11+
- Git

### Project cloning


git clone https://github.com/Mouhawos/Spidercrypt_CLI.git
cd Spidercrypt_CLI
Creating a virtual environment
Windows
python -m venv spidercrypt-venv
.\spidercrypt-venv\Scripts\activate
Linux / macOS
python3 -m venv spidercrypt-venv
source spidercrypt-venv/bin/activate
Installing dependencies
pip install -r requirements.txt
▶️ Usage
Display available commands:

python cli.py
Result:

Commands:

check-prompt
data-ghosting
fingerprint
output-sanitizer
prompt-firewall
scan-code
detect-poisoning
🔍 Code Analysis
Analyzes a source file and generates a report.

python cli.py scan-code vulnerable_test.py --output audit.json
Result:

Analysis complete → audit.json
🧠 Prompt Injection Detection
python cli.py check-prompt prompt.txt
Example (attack detected)
{
"risk_score": 0.833,

"allowed": false,

"severity": "high"

}
🔐 AI Firewall
Automatically blocks dangerous prompts.

python cli.py prompt-firewall prompt.txt
Example:

🚫 Prompt blocked
🕵️ Sensitive Data Masking (PII)
python cli.py data-ghosting pii.txt --output ghosted.txt
Result:

→ Masked text saved
🧹 Output Cleanup
Detects XSS, scripts, and injections.

python cli.py output-sanitizer output.txt
Example:

{
"status": "sanitized",

"risky_patterns": ["<script>"]

🧬 Data Poisoning Detection
Analyzes ML datasets.

python cli.py detect-poisoning dataset.json
Example (attack detected)
{
"poisoning_detected": true,

"severity": "high"

}
⚠️ Data poisoning suspected
📊 Score Interpretation
Level Significance
Low Low Risk
Medium Moderate Risk
High Critical Threat
🔧 CI/CD Integration
Spidercrypt CLI can be integrated into:

GitHub Actions

GitLab CI

Jenkins

MLOps Pipelines

Example GitHub Actions
- name: Scan Security
run: |
python cli.py scan-code app.py --output report.json
🎯 Use Cases
Securing Chatbots

AI SaaS Protection

ML Auditing

API Gateway

Autonomous Agents

Data Pipelines

Cloud Security

📁 Project Structure
Spidercrypt_CLI/
├── cli.py
├── engines/
├── detectors/
├── utils/
├── reports/
├── requirements.txt
└── README.md
📌 Best Practices
✔ Scan user prompts
✔ Verify datasets before training
✔ Filter all outputs
✔ Log reports
✔ Automate Audits

📄 License
This project is licensed under the MIT License.

See the LICENSE file for more information.

👨‍💻 Author
Developed by Mouhamed Sow
Founder of Spidercrypt

📧 Contact: support@spidercrypt.io
🌐 Website: https://spidercrypt.io

⭐ Support
If this project helps you:

Add a ⭐ on GitHub

Share it

Contribute

🛠️ Roadmap

Web Dashboard

REST API

Advanced ML Models

Real-Time Monitoring

Cloud Platform

Enterprise Version
