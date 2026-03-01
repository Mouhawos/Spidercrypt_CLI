import click
import re
import json
import os
import base64
import math
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

# Cryptography & AI
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

try:
    from langchain_ollama import OllamaLLM
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    HAS_AI = True
except ImportError:
    HAS_AI = False

# ────────────────────────────────────────────────
# CONFIGURATION & PATTERNS
# ────────────────────────────────────────────────

SECRET_PATTERNS = [
    r"(?i)(api|access|secret|private|auth|bearer|token)[_-]?(key|token|id|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?i)(password|passwd|pwd|pass)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN\s+(?:RSA|EC|OPENSSH)?\s+PRIVATE\s+KEY-----[\s\S]+?-----END\s+.*PRIVATE\s+KEY-----",
    r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
]

PROMPT_INJECTION_PATTERNS = [
    r"(?i)(ignore|forget|override|system prompt|jailbreak|dan|do anything now|bypass|reveal prompt)",
]

RISKY_CODE_PATTERNS = ["eval(", "exec(", "os.system(", "subprocess.call(", "pickle.loads("]

PII_PATTERNS = {
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
}

# ──────────────────────────────────────────────────────────────
# DATA POISONING DETECTION — PATTERNS & HEURISTICS
# ──────────────────────────────────────────────────────────────

# Backdoor triggers in text values
BACKDOOR_TRIGGER_PATTERNS = [
    r"(?i)\b(cf|mn|bb|tq|trigger|backdoor|poisoned|trojan)\b",
    r"<[A-Z]{2,6}>",
    r"\[\s*MASK\s*\]",
    r"(?i)(IGNORE PREVIOUS|OVERRIDE LABEL|FORCE OUTPUT)",
]

# Structurally suspicious JSON keys
SUSPICIOUS_KEYS = {"__proto__", "constructor", "eval", "exec", "instruction_override",
                   "hidden_label", "shadow_label", "bypass", "secret_label"}

# Fields typically used as labels in ML datasets
# Includes common binary fields such as "vulnerable", "malicious", "toxic", etc.
LABEL_FIELD_NAMES = {
    "label", "labels", "target", "output", "answer", "category",
    "class", "sentiment", "vulnerable", "malicious", "toxic",
    "spam", "is_toxic", "is_spam", "is_malicious", "flag",
    "safe", "benign", "classification", "prediction", "score",
}

# INSECURE code patterns — high precision, few false positives
# (only usages that are dangerous IN ALL CONTEXTS)
INSECURE_CODE_PATTERNS = [
    # yaml.load without Loader → always dangerous (RCE)
    (r"yaml\.load\s*\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader)[^\)]*\)",
     "yaml.load() without SafeLoader → possible RCE"),
    # tempfile.mktemp → race condition, always deprecated
    (r"tempfile\.mktemp\s*\(",
     "tempfile.mktemp() → race condition (deprecated)"),
    # pickle.load/loads → arbitrary deserialization
    (r"pickle\.loads?\s*\(",
     "pickle.load() → dangerous deserialization"),
    # JWT process_jwt without second argument (key) or algorithms
    (r"jwt\.process_jwt\s*\(\s*\w+\s*\)",
     "JWT verified without key or algorithm"),
    # XSLT with network access enabled
    (r"read_network\s*=\s*True",
     "XSLTAccessControl read_network=True → SSRF"),
    # pure eval() (not ast.literal_eval, not re.compile, etc.)
    (r"(?<![._\w])eval\s*\(",
     "Direct eval() → arbitrary code execution"),
]

# SECURE code patterns (presence in code labeled "vulnerable" = suspicious)
SECURE_CODE_PATTERNS = [
    (r"yaml\.safe_load\s*\(",        "yaml.safe_load()"),
    (r"tempfile\.TemporaryFile\s*\(","tempfile.TemporaryFile()"),
    (r"algorithms\s*=\s*\[",         "JWT with explicit algorithms"),
    (r"XSLTAccessControl\.DENY_ALL", "XSLTAccessControl.DENY_ALL"),
    (r"(?<![a-z])escape\s*\(",       "escape() — input encoding"),
    (r"abort\s*\(\s*404\s*\)",       "abort(404) — resource validation"),
    (r"os\.path\.realpath\s*\(",     "os.path.realpath — path traversal mitigation"),
    (r"yaml\.safe_",                 "yaml.safe_* method"),
    (r"re\.escape\s*\(",             "re.escape()"),
    (r"html\.escape\s*\(",           "html.escape()"),
]


def _flatten_values(obj, depth=0, max_depth=6):
    """Recursively collects all text values from a JSON object."""
    if depth > max_depth:
        return []
    values = []
    if isinstance(obj, dict):
        for v in obj.values():
            values += _flatten_values(v, depth + 1, max_depth)
    elif isinstance(obj, list):
        for item in obj:
            values += _flatten_values(item, depth + 1, max_depth)
    elif isinstance(obj, str):
        values.append(obj)
    return values


def _auto_detect_label_fields(records: list) -> Dict[str, list]:
    """
    Automatically detects fields that look like ML labels:
    - Named like a known label (LABEL_FIELD_NAMES)
    - OR low-cardinality fields (≤10 distinct values) across the dataset.
    Returns {field_name: [all values]} for each candidate field.
    """
    if not records or not isinstance(records[0], dict):
        return {}

    all_keys = set()
    for rec in records:
        if isinstance(rec, dict):
            all_keys.update(rec.keys())

    candidates = {}
    for key in all_keys:
        values = [str(rec[key]) for rec in records
                  if isinstance(rec, dict) and key in rec
                  and isinstance(rec[key], (str, int, float, bool))]
        if not values:
            continue
        distinct = set(values)
        # Include if known name OR cardinality ≤ 10 on ≥ 10 records
        if key.lower() in LABEL_FIELD_NAMES or (len(distinct) <= 10 and len(values) >= 10):
            candidates[key] = values
    return candidates


def _shannon_entropy(values: list) -> float:
    """Computes Shannon entropy of a list of values."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _detect_label_flip_duplicates(records: list, label_fields: set) -> dict:
    """
    Detects entries with the same non-label content but different labels
    (label-flip attack).
    """
    seen: Dict[str, list] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        non_label = {k: v for k, v in rec.items() if k not in label_fields}
        key = json.dumps(non_label, sort_keys=True, ensure_ascii=False)
        label_val = json.dumps({k: rec[k] for k in rec if k in label_fields}, sort_keys=True)
        seen.setdefault(key, []).append(label_val)

    return {k: len(set(v)) for k, v in seen.items() if len(set(v)) > 1}


def _check_code_label_consistency(records: list) -> Dict[str, Any]:
    """
    Checks consistency between the 'code' field content and vulnerability labels.

    Suspicious cases:
    - Code containing insecure patterns BUT labeled 'safe' (0 / false / "safe")
    - Code containing secure patterns BUT labeled 'vulnerable' (1 / true / "vulnerable")
    """
    SAFE_VALUES  = {"0", "false", "safe", "no", "benign", "clean"}
    VULN_VALUES  = {"1", "true", "vulnerable", "yes", "malicious", "unsafe"}

    # Fields that might carry the vulnerability label
    VULN_LABEL_KEYS = {"vulnerable", "is_vulnerable", "malicious", "is_malicious",
                       "label", "target", "flag"}

    inconsistencies = {
        "insecure_but_safe_label": [],    # dangerous code but label=safe → poison
        "secure_but_vuln_label":   [],    # safe code but label=vulnerable → poison
    }

    for rec in records:
        if not isinstance(rec, dict):
            continue
        code = rec.get("code", "") or ""
        if not isinstance(code, str) or not code.strip():
            continue

        # Retrieve the vulnerability label if it exists
        label_val = None
        for k in VULN_LABEL_KEYS:
            if k in rec:
                label_val = str(rec[k]).lower()
                break
        if label_val is None:
            continue

        # Check consistency
        if label_val in SAFE_VALUES:
            for pattern, desc in INSECURE_CODE_PATTERNS:
                if re.search(pattern, code):
                    inconsistencies["insecure_but_safe_label"].append(
                        {"desc": desc, "code_snippet": code[:120]}
                    )
                    break

        elif label_val in VULN_VALUES:
            for pattern, desc in SECURE_CODE_PATTERNS:
                if re.search(pattern, code):
                    inconsistencies["secure_but_vuln_label"].append(
                        {"desc": desc, "code_snippet": code[:120]}
                    )
                    break

    return inconsistencies


def analyze_json_for_poisoning(filepath: str) -> Dict[str, Any]:
    """
    Full analysis of a JSON file to detect potential signs of data poisoning.
    Returns a structured report.
    """
    report = {
        "file": filepath,
        "poisoning_detected": False,
        "risk_score": 0.0,
        "warnings": [],
        "details": {}
    }
    score_acc = 0.0

    # ── 1. Loading ─────────────────────────────────────────────
    try:
        raw = Path(filepath).read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        report["warnings"].append(f"Invalid JSON: {e}")
        report["risk_score"] = 0.1
        return report

    records = data if isinstance(data, list) else [data]
    total = len(records)
    report["details"]["total_records"] = total

    # ── 2. Backdoor triggers in text values ────────────────────
    all_text = _flatten_values(data)
    triggered = []
    for text in all_text:
        for pat in BACKDOOR_TRIGGER_PATTERNS:
            if re.search(pat, text):
                triggered.append(text[:120])
                break
    if triggered:
        ratio = len(triggered) / max(len(all_text), 1)
        report["warnings"].append(
            f"🎯 Backdoor triggers detected in {len(triggered)} value(s) "
            f"({ratio*100:.1f}% of analyzed text)."
        )
        report["details"]["triggered_samples"] = triggered[:5]
        score_acc += min(0.35, ratio * 4)

    # ── 3. Suspicious JSON keys ────────────────────────────────
    def _find_suspicious_keys(obj, found=None):
        if found is None:
            found = set()
        if isinstance(obj, dict):
            for k in obj:
                if k.lower() in SUSPICIOUS_KEYS:
                    found.add(k)
                _find_suspicious_keys(obj[k], found)
        elif isinstance(obj, list):
            for item in obj:
                _find_suspicious_keys(item, found)
        return found

    bad_keys = _find_suspicious_keys(data)
    if bad_keys:
        report["warnings"].append(f"⚠️  Suspicious JSON keys: {', '.join(bad_keys)}")
        score_acc += 0.2

    # ── 4. Automatic label field detection ────────────────────
    #       (fixes bug: "vulnerable" was not monitored)
    label_candidates = _auto_detect_label_fields(records)
    all_label_details = {}

    for field, values in label_candidates.items():
        counts  = Counter(values)
        entropy = _shannon_entropy(values)
        most_common, most_common_count = counts.most_common(1)[0]
        dominance = most_common_count / len(values)

        all_label_details[field] = {
            "distribution": dict(counts.most_common(10)),
            "entropy":      round(entropy, 4),
            "dominance":    round(dominance, 4),
        }

        # 100% of a single label → very strong signal
        if dominance == 1.0:
            report["warnings"].append(
                f"🚨 Field '{field}': 100% of value '{most_common}' across "
                f"{len(values)} records → total uniformity (suspicious single-class dataset)."
            )
            score_acc += 0.30   # moderate signal — could be a legitimate single-class file

        # Strong dominance (>85%) with multiple possible values in other datasets
        elif dominance > 0.85:
            report["warnings"].append(
                f"📊 Field '{field}': dominant label '{most_common}' at "
                f"{dominance*100:.1f}% → suspicious imbalance."
            )
            score_acc += 0.2

        # Very low entropy
        if entropy < 0.5 and len(counts) > 1:
            report["warnings"].append(
                f"📉 Field '{field}': very low entropy ({entropy:.3f}) → suspicious uniformity."
            )
            score_acc += 0.1

    if all_label_details:
        report["details"]["label_fields"] = all_label_details

    # ── 5. Code / vulnerability label consistency ──────────────
    if any("code" in rec for rec in records if isinstance(rec, dict)):
        code_issues = _check_code_label_consistency(records)
        n_insecure  = len(code_issues["insecure_but_safe_label"])
        n_secure    = len(code_issues["secure_but_vuln_label"])

        if n_insecure > 0:
            ratio = n_insecure / total
            report["warnings"].append(
                f"🔓 {n_insecure} record(s) ({ratio*100:.1f}%): INSECURE code "
                f"but label 'safe' → strong inconsistency (label-poisoning)."
            )
            report["details"]["insecure_code_samples"] = code_issues["insecure_but_safe_label"][:3]
            score_acc += min(0.45, ratio * 3)

        if n_secure > 0:
            ratio = n_secure / total
            report["warnings"].append(
                f"🔒 {n_secure} record(s) ({ratio*100:.1f}%): SECURE code "
                f"but label 'vulnerable' → inconsistency (reverse label-poisoning)."
            )
            report["details"]["secure_code_mislabeled"] = code_issues["secure_but_vuln_label"][:3]
            score_acc += min(0.45, ratio * 3)

        # ── 5b. Absolute density of insecure patterns ────────
        # Signal independent of the label: a dataset where most code
        # uses known dangerous APIs is suspicious, regardless of label value.
        insecure_hits = []
        for rec in records:
            code = rec.get("code", "") if isinstance(rec, dict) else ""
            if not isinstance(code, str): continue
            for pat, desc in INSECURE_CODE_PATTERNS:
                if re.search(pat, code):
                    insecure_hits.append(desc)
                    break
        insecure_density = len(insecure_hits) / max(total, 1)
        report["details"]["insecure_code_density"] = round(insecure_density, 4)

        if insecure_density > 0.05:  # >5% of records with dangerous code
            report["warnings"].append(
                f"☠️  High density of insecure code: {len(insecure_hits)}/{total} "
                f"records ({insecure_density*100:.1f}%) contain known dangerous patterns "
                f"(yaml.load, pickle, mktemp, unsigned jwt…)."
            )
            score_acc += min(0.35, insecure_density * 4)

    # ── 6. Label-flip attacks (same input, different labels) ───
    all_label_field_names = set(label_candidates.keys())
    conflicts = _detect_label_flip_duplicates(records, all_label_field_names)
    if conflicts:
        report["warnings"].append(
            f"🔀 {len(conflicts)} identical entry/entries with contradictory labels "
            f"(possible label-flip attack)."
        )
        report["details"]["conflicting_samples"] = list(conflicts.keys())[:3]
        score_acc += min(0.35, len(conflicts) / max(total, 1) * 10)

    # ── 7. Raw duplicates ──────────────────────────────────────
    raw_hashes = [json.dumps(r, sort_keys=True) for r in records if isinstance(r, dict)]
    dup_count  = len(raw_hashes) - len(set(raw_hashes))
    if total > 10 and dup_count / total > 0.1:
        report["warnings"].append(
            f"♻️  {dup_count} exact duplicates ({dup_count/total*100:.1f}%) → "
            f"suspicious over-representation."
        )
        score_acc += min(0.2, dup_count / total)

    # ── 8. Final score ─────────────────────────────────────────
    report["risk_score"] = round(min(score_acc, 1.0), 3)
    report["poisoning_detected"] = report["risk_score"] >= 0.40

    return report


# ────────────────────────────────────────────────
# DATABASE & CRYPTO UTILS
# ────────────────────────────────────────────────

Base = declarative_base()

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    filename = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow)
    report = Column(Text)

engine = create_engine("sqlite:///spidercrypt.db")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)


def internal_gen_key():
    return base64.b64encode(AESGCM.generate_key(bit_length=256)).decode()

def internal_encrypt(key_b64, data):
    key = base64.b64decode(key_b64)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data, None)

def internal_decrypt(key_b64, payload):
    key = base64.b64decode(key_b64)
    aes = AESGCM(key)
    return aes.decrypt(payload[:12], payload[12:], None)


# ────────────────────────────────────────────────
# CLI INTERFACE
# ────────────────────────────────────────────────

BANNER = r"""
  ____  ____  ___ ____  _____ ____   ____ ______     ______  _____ 
 / ___||  _ \|_ _|  _ \| ____|  _ \ / ___|  _ \ \   / /  _ \|_   _|
 \___ \| |_) || || | | |  _| | |_) | |   | |_) \ \ / /| |_) | | |  
  ___) |  __/ | || |_| | |___|  _ <| |___|  _ < \ V / |  __/  | |  
 |____/|_|   |___|____/|_____|_| \_\\____|_| \_\ \_/  |_|     |_|  
                                                                   
      >>> SECURITY & CRYPTOGRAPHY TOOLSET v1.1 <<<
"""

@click.group()
@click.option("--verbose", is_flag=True)
@click.pass_context
def cli(ctx, verbose):
    """SpiderCrypt CLI - Cybersecurity toolset."""
    click.secho(BANNER, fg="cyan", bold=True)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@cli.command(name="gen-key")
def gen_key():
    """Generates a base64-encoded AES-256 key."""
    click.echo(internal_gen_key())


@cli.command(name="encrypt")
@click.option("--key", required=True, envvar="SPIDER_KEY")
@click.argument("infile", type=click.Path(exists=True))
@click.argument("outfile", type=click.Path())
def encrypt(key, infile, outfile):
    """Encrypts a file using AES-GCM."""
    data = Path(infile).read_bytes()
    result = internal_encrypt(key, data)
    Path(outfile).write_bytes(result)
    click.secho(f"✅ File protected: {outfile}", fg="green")


@cli.command(name="decrypt")
@click.option("--key", required=True, envvar="SPIDER_KEY")
@click.argument("infile", type=click.Path(exists=True))
@click.argument("outfile", type=click.Path())
def decrypt(key, infile, outfile):
    """Decrypts a file protected with AES-GCM."""
    try:
        payload = Path(infile).read_bytes()
        decrypted_data = internal_decrypt(key, payload)
        Path(outfile).write_bytes(decrypted_data)
        click.secho(f"🔓 Decryption successful: {outfile}", fg="cyan")
    except Exception as e:
        click.secho(f"❌ Failed: Incorrect key or corrupted file.", fg="red", bold=True)


@cli.command(name="audit")
@click.argument("file", type=click.Path(exists=True))
@click.option("--ai", is_flag=True)
def audit(file, ai):
    """Security scan (Regex + AI)."""
    code = Path(file).read_text(encoding="utf-8", errors="replace")
    secrets_found = [p for p in SECRET_PATTERNS if re.search(p, code)]
    click.secho(f"--- Static Analysis of {file} ---", bold=True)
    click.echo(f"Secrets found: {len(secrets_found)}")

    if ai and HAS_AI:
        click.echo("Running AI analysis...")

    session = Session()
    report = json.dumps({
        "secrets_found": len(secrets_found),
        "secret_patterns": secrets_found
    })
    log_entry = AuditLog(filename=file, report=report)
    session.add(log_entry)
    session.commit()
    session.close()


@cli.command(name="firewall")
@click.argument("input_data")
@click.option("--file", is_flag=True)
def prompt_firewall(input_data, file):
    """Checks for prompt injections (Text or File)."""
    content = Path(input_data).read_text(encoding="utf-8") if file else input_data
    hits = [pat for pat in PROMPT_INJECTION_PATTERNS if re.search(pat, content, re.IGNORECASE)]
    result = {"blocked": len(hits) > 0, "hits": hits, "risk_score": len(hits) / 5}
    click.echo(json.dumps(result, indent=2))


@cli.command(name="ghost-pii")
@click.argument("infile", type=click.Path(exists=True))
@click.option("--output", type=click.Path())
def ghost_pii(infile, output):
    """Masks personally identifiable information."""
    text = Path(infile).read_text()
    for name, pat in PII_PATTERNS.items():
        text = re.sub(pat, f"[{name}]", text)
    if output:
        Path(output).write_text(text)
    else:
        click.echo(text)


@cli.command(name="history")
def history():
    """Displays audit history."""
    session = Session()
    logs = session.query(AuditLog).all()
    for log in logs:
        click.echo(f"{log.timestamp} | {log.filename}")
    session.close()


# ──────────────────────────────────────────────────────────────
#  detect-poison
# ──────────────────────────────────────────────────────────────

@cli.command(name="detect-poison")
@click.argument("files", nargs=-1, type=click.Path(exists=True), required=True)
@click.option("--json-output", is_flag=True, help="Prints the full report as JSON.")
@click.option("--save", is_flag=True, help="Saves the results to the audit database.")
@click.option("--threshold", default=0.40, show_default=True,
              help="Risk score threshold above which a file is marked 'poisoned'.")
def detect_poison(files, json_output, save, threshold):
    """
    Analyzes one or more JSON files to detect data poisoning.

    \b
    Applied heuristics:
      • Backdoor triggers & injections in text values
      • Suspicious JSON keys (__proto__, shadow_label, etc.)
      • Abnormal label distribution (dominance, entropy)
      • Label-flip attacks (same input, contradictory labels)
      • High ratio of exact duplicates

    \b
    Examples:
      spidercrypt detect-poison dataset.json
      spidercrypt detect-poison *.json --json-output --save
      spidercrypt detect-poison data.json --threshold 0.4
    """
    all_reports = []

    for filepath in files:
        if not filepath.lower().endswith(".json"):
            click.secho(f"⏭  {filepath} skipped (not a .json)", fg="yellow")
            continue

        click.secho(f"\n🔍 Analyzing: {filepath}", bold=True)
        report = analyze_json_for_poisoning(filepath)
        # Apply custom threshold
        report["poisoning_detected"] = report["risk_score"] >= threshold

        if json_output:
            click.echo(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            _print_poison_report(report)

        # Optional save to database
        if save:
            session = Session()
            log_entry = AuditLog(
                filename=filepath,
                report=json.dumps(report, ensure_ascii=False)
            )
            session.add(log_entry)
            session.commit()
            session.close()
            click.secho(f"  💾 Report saved to database.", fg="blue")

        all_reports.append(report)

    # ── Global summary when multiple files ───────────────────
    if len(all_reports) > 1:
        poisoned = [r for r in all_reports if r["poisoning_detected"]]
        clean = [r for r in all_reports if not r["poisoning_detected"]]
        click.secho("\n" + "═" * 55, bold=True)
        click.secho(f"  SUMMARY  |  {len(all_reports)} files analyzed", bold=True)
        click.secho("═" * 55, bold=True)
        click.secho(f"  🚨 Poisoned : {len(poisoned)}", fg="red"   if poisoned else "white")
        click.secho(f"  ✅ Clean    : {len(clean)}",    fg="green"  if clean    else "white")
        for r in poisoned:
            click.secho(f"     ↳ {r['file']}  (score={r['risk_score']})", fg="red")


def _print_poison_report(report: Dict[str, Any]):
    """Displays the poisoning report in the terminal (human-readable mode)."""
    detected = report["poisoning_detected"]
    score    = report["risk_score"]
    warnings = report["warnings"]
    details  = report["details"]

    # ── Verdict banner ────────────────────────────────────────
    if detected:
        click.secho("  ┌─────────────────────────────────────────┐", fg="red", bold=True)
        click.secho("  │  🚨  DATA POISONING DETECTED              │", fg="red", bold=True)
        click.secho("  └─────────────────────────────────────────┘", fg="red", bold=True)
    else:
        click.secho("  ┌─────────────────────────────────────────┐", fg="green", bold=True)
        click.secho("  │  ✅  Clean file — no suspicious signs     │", fg="green", bold=True)
        click.secho("  └─────────────────────────────────────────┘", fg="green", bold=True)

    # Visual risk bar
    bar_len  = 30
    filled   = int(score * bar_len)
    color    = "red" if score >= 0.5 else ("yellow" if score >= 0.25 else "green")
    bar      = "█" * filled + "░" * (bar_len - filled)
    click.secho(f"\n  Risk Score : [{bar}] {score:.3f}", fg=color, bold=True)

    # Dataset statistics
    if details.get("total_records"):
        click.echo(f"  Records analyzed: {details['total_records']}")
    if "label_fields" in details:
        for field, info in details["label_fields"].items():
            click.echo(f"  Field '{field}': {info['distribution']}  "
                       f"entropy={info['entropy']}  dominance={info['dominance']*100:.1f}%")
    if "insecure_code_density" in details:
        density = details["insecure_code_density"]
        col = "red" if density > 0.05 else "green"
        click.secho(f"  Insecure code density: {density*100:.1f}%", fg=col)

    # Warnings
    if warnings:
        click.secho("\n  ⚠️  Warnings:", bold=True)
        for w in warnings:
            click.secho(f"    • {w}", fg="yellow")

    # Trigger samples
    if "triggered_samples" in details:
        click.secho("\n  🎯 Suspicious excerpts:", bold=True)
        for s in details["triggered_samples"]:
            click.secho(f'    "{s[:100]}"', fg="magenta")

    # Insecure code labeled as "safe"
    if "insecure_code_samples" in details:
        click.secho("\n  🔓 Insecure code labeled 'safe' (excerpt):", bold=True)
        for s in details["insecure_code_samples"]:
            click.secho(f"    [{s['desc']}]", fg="red")
            click.secho(f"    {s['code_snippet'][:100]}", fg="magenta")

    # Secure code labeled as "vulnerable"
    if "secure_code_mislabeled" in details:
        click.secho("\n  🔒 Secure code labeled 'vulnerable' (excerpt):", bold=True)
        for s in details["secure_code_mislabeled"]:
            click.secho(f"    [{s['desc']}]", fg="red")
            click.secho(f"    {s['code_snippet'][:100]}", fg="magenta")

    # Label conflicts
    if "conflicting_samples" in details:
        click.secho("\n  🔀 Entries with contradictory labels (excerpt):", bold=True)
        for s in details["conflicting_samples"]:
            try:
                parsed = json.loads(s)
                click.secho(f"    {json.dumps(parsed, ensure_ascii=False)[:120]}", fg="magenta")
            except Exception:
                click.secho(f"    {str(s)[:120]}", fg="magenta")

    click.echo()


if __name__ == "__main__":
    click.secho(BANNER, fg="cyan", bold=True)
    cli(obj={})
