import click
import re
import json
import string
import statistics
from pathlib import Path
from typing import List, Dict, Any, Tuple

# ────────────────────────────────────────────────
# Constantes & Patterns
# ────────────────────────────────────────────────

SECRET_PATTERNS: List[str] = [
    r"(?i)(api|access|secret|private|auth|bearer|token)[_-]?(key|token|id|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?i)(password|passwd|pwd|pass)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    r"AKIA[0-9A-Z]{16}",
    r"(?i)aws_access_key_id\s*=\s*['\"][A-Z0-9]{20}['\"]",
    r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
    r"sk_live_[0-9a-zA-Z]{24,}",
    r"rk_live_[0-9a-zA-Z]{24,}",
    r"sk-[A-Za-z0-9]{20,}",
    r"sk-ant-[A-Za-z0-9]{40,}",
    r"-----BEGIN\s+(?:RSA|EC|OPENSSH)?\s+PRIVATE\s+KEY-----[\s\S]+?-----END\s+.*PRIVATE\s+KEY-----",
    r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
]

PROMPT_INJECTION_PATTERNS: List[str] = [
    r"(?i)(ignore|forget|override|reset|new|forget all previous|stop being|no longer follow)",
    r"(?i)(system prompt|system message|you are now|act as|roleplay|developer mode|maintenance mode)",
    r"(?i)(jailbreak|dan|do anything now|unrestricted|god mode|maximum truth|anti-ai)",
    r"(?i)(output only|respond only with|print the|reveal|expose|show hidden)",
    r"(?i)(bypass|disable|turn off|remove|ignore rules|no restrictions)",
    r"(?i)(from now on|starting now|in this chat|for this session)",
]

RISKY_CODE_PATTERNS = [
    "eval(", "exec(", "os.system(", "subprocess.call(", "subprocess.Popen(",
    "pickle.loads(", "pickle.load(", "yaml.load(", "yaml.full_load(",
    "os.popen(", "commands.getoutput(", "execfile(",
]

PII_PATTERNS = {
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "PHONE": r"\b(?:\+?\d{1,3}[- ]?)?(?:\(\d{3}\)|\d{3})[- ]?\d{3}[- ]?\d{4}\b",
    "SSN_US": r"\b\d{3}-\d{2}-\d{4}\b",
    "API_KEY": r"(?i)(key|token|secret|password|api_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
}

PROMPT_FIREWALL_PATTERNS = PROMPT_INJECTION_PATTERNS + [
    r"(?i)(act as|you are now|roleplay|pretend|simulate|become|transform into)",
    r"(?i)(output format|json|xml|code block|reveal prompt|show instructions)",
    r"(?i)(no ethics|no morals|unrestricted|maximum truth|anti-filter)",
    r"(?i)(repeat after me|echo|copy this|follow exactly)",
]

# ────────────────────────────────────────────────
# Fonctions de base
# ────────────────────────────────────────────────

def normalize_text(raw: bytes) -> str:
    for encoding, errors in [("utf-8", "strict"), ("utf-16", "strict"), ("latin-1", "ignore")]:
        try:
            return raw.decode(encoding, errors=errors)
        except UnicodeDecodeError:
            continue
    return ""

def detect_secrets(text: str) -> List[Dict[str, str]]:
    findings = []
    for pattern in SECRET_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL):
            excerpt = match.group(0)[:100] + ("..." if len(match.group(0)) > 100 else "")
            findings.append({"type": "hardcoded_secret", "pattern": pattern, "excerpt": excerpt})
    return findings

def scan_code_injections(code: str) -> List[str]:
    return [pat for pat in RISKY_CODE_PATTERNS if pat in code]

def detect_prompt_injection(prompt: str) -> Dict[str, Any]:
    hits = [pat for pat in PROMPT_INJECTION_PATTERNS if re.search(pat, prompt, re.IGNORECASE)]
    score = min(len(hits) / len(PROMPT_INJECTION_PATTERNS), 1.0)
    return {
        "risk_score": round(score, 3),
        "hits": hits,
        "allowed": len(hits) <= 1,
        "severity": "low" if len(hits) <= 1 else "medium" if len(hits) <= 3 else "high",
    }

def mask_sensitive(text: str) -> str:
    text = re.sub(r"\b\d{13,19}\b", "[CARD_NUMBER]", text)
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", text)
    return text

def analyze_poisoning_from_logs(data: list) -> Dict[str, Any]:
    prompts = [
        str(item.get("prompt", "") or item.get("query", ""))
        for item in data
        if item.get("prompt") or item.get("query")
    ]

    if len(prompts) < 5:
        return {"error": "Pas assez de données pour analyse"}

    entropies = [
        1.0 - sum(c.isprintable() for c in p) / max(len(p), 1)
        for p in prompts
    ]

    avg_entropy = sum(entropies) / len(entropies)
    unique_ratio = len(set(prompts)) / len(prompts)
    repeated = sum(1 for p in prompts if prompts.count(p) > 2) / len(prompts)

    suspicious = (
        avg_entropy > 0.28
        or unique_ratio < 0.45
        or repeated > 0.20
    )

    return {
        "records": len(prompts),
        "avg_entropy": round(avg_entropy, 3),
        "unique_ratio": round(unique_ratio, 3),
        "repeated_ratio": round(repeated, 3),
        "poisoning_detected": suspicious,
        "severity": "high" if suspicious else "low",
    }



# ────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────

@click.group()
@click.option("--verbose", is_flag=True, help="Affiche plus de détails")
@click.pass_context
def cli(ctx, verbose):
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

# ────────────────────────────────────────────────
# Commandes gratuites
# ────────────────────────────────────────────────

@cli.command(name="scan-code")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", default="audit.json", type=Path)
@click.pass_context
def scan_code(ctx, file: Path, output: Path):
    code = file.read_text(encoding="utf-8", errors="replace")
    secrets = detect_secrets(code)
    injections = scan_code_injections(code)
    risk_score = min((len(secrets) + len(injections)) * 0.2, 1.0)
    report = {
        "file": str(file),
        "secrets_found": len(secrets),
        "secrets": secrets[:8],
        "injections": injections,
        "risk_score": round(risk_score, 2),
    }
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    click.secho(f"Analyse terminée → {output}", fg="green")
    if ctx.obj["verbose"] and secrets:
        click.secho("\nSecrets détectés :", fg="yellow")
        for s in secrets:
            click.echo(f"  • {s['excerpt']}")

@cli.command(name="check-prompt")
@click.argument("prompt_file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def check_prompt(ctx, prompt_file: Path):
    prompt = prompt_file.read_text(encoding="utf-8", errors="replace")
    result = detect_prompt_injection(prompt)
    result["sanitized_prompt"] = mask_sensitive(prompt)[:300] + "..."
    click.echo(json.dumps(result, indent=2, ensure_ascii=False))
    if not result["allowed"]:
        click.secho("⚠️  Prompt potentiellement malveillant !", fg="red", bold=True)

@cli.command(name="prompt-firewall")
@click.argument("input", type=str)
@click.option("--threshold", default=0.35, type=float)
@click.pass_context
def prompt_firewall(ctx, input: str, threshold: float):
    prompt = Path(input).read_text(encoding="utf-8", errors="replace") if Path(input).exists() else input
    hits = [pat for pat in PROMPT_FIREWALL_PATTERNS if re.search(pat, prompt, re.IGNORECASE)]
    score = min(len(hits) / len(PROMPT_FIREWALL_PATTERNS), 1.0)
    result = {
        "risk_score": round(score, 3),
        "hits": hits[:6],
        "blocked": score >= threshold,
        "action": "BLOCKED" if score >= threshold else "ALLOWED",
        "severity": "high" if score > 0.6 else "medium" if score >= threshold else "low",
        "preview": prompt[:180] + "..." if len(prompt) > 180 else prompt
    }
    click.echo(json.dumps(result, indent=2, ensure_ascii=False))
    click.secho("🚫 Prompt bloqué" if result["blocked"] else "✅ Prompt autorisé", fg="red" if result["blocked"] else "green")

@cli.command(name="data-ghosting")
@click.argument("input", type=str)
@click.option("--output", default=None)
@click.pass_context
def data_ghosting(ctx, input: str, output: str | None):
    text = Path(input).read_text(encoding="utf-8", errors="replace") if Path(input).exists() else input
    masked = text
    applied = []
    for name, pat in PII_PATTERNS.items():
        count = len(re.findall(pat, masked))
        if count > 0:
            applied.append(f"{name} ×{count}")
            masked = re.sub(pat, f"[{name}]", masked)
    result = {
        "masked_items": applied,
        "status": "ghosted" if applied else "clean",
        "preview_original": text[:220] + "..." if len(text) > 220 else text,
        "preview_masked": masked[:220] + "..." if len(masked) > 220 else masked
    }
    click.echo(json.dumps(result, indent=2))
    if output:
        Path(output).write_text(masked, encoding="utf-8")
        click.echo(f"→ Texte masqué sauvegardé dans : {output}")

@cli.command(name="output-sanitizer")
@click.argument("input", type=str)
@click.pass_context
def output_sanitizer(ctx, input: str):
    text = Path(input).read_text(encoding="utf-8", errors="replace") if Path(input).exists() else input
    sanitized = text
    masked_count = 0
    for name, pat in PII_PATTERNS.items():
        count = len(re.findall(pat, sanitized))
        masked_count += count
        sanitized = re.sub(pat, f"[SANITIZED_{name}]", sanitized)
    risky_patterns = ["<script>", "javascript:", "onerror=", "eval(", "innerHTML", "document.cookie"]
    risky_hits = [p for p in risky_patterns if p.lower() in sanitized.lower()]
    result = {
        "pii_masked_count": masked_count,
        "risky_content_detected": bool(risky_hits),
        "risky_patterns": risky_hits,
        "status": "sanitized" if masked_count > 0 or risky_hits else "clean",
        "preview": sanitized[:350] + "..." if len(sanitized) > 350 else sanitized
    }
    click.echo(json.dumps(result, indent=2))
    if risky_hits:
        click.secho("⚠️ Contenu potentiellement dangereux dans l'output !", fg="red")

@cli.command(name="fingerprint")
@click.argument("log_file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def fingerprint(ctx, log_file: Path):
    if not log_file.exists():
        click.secho(f"Fichier non trouvé : {log_file}", fg="red")
        return
    try:
        data = json.loads(log_file.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(data, list):
            raise ValueError("Le fichier doit contenir une liste JSON")
    except Exception as e:
        click.secho(f"Erreur lecture JSON : {e}", fg="red")
        return
    prompts = [str(item.get("prompt", "") or item.get("query", "")) for item in data if item.get("prompt") or item.get("query")]
    if len(prompts) < 5:
        click.echo("Pas assez de prompts pour une analyse fingerprint fiable.")
        return
    entropies = [1.0 - sum(c.isprintable() for c in p)/max(len(p),1) for p in prompts]
    avg_entropy = sum(entropies) / len(entropies)
    unique_ratio = len(set(prompts)) / len(prompts)
    repeated = sum(1 for p in prompts if prompts.count(p) > 2) / len(prompts)
    suspicious = avg_entropy > 0.28 or unique_ratio < 0.45 or repeated > 0.20
    result = {
        "prompts_analyzed": len(prompts),
        "avg_entropy": round(avg_entropy, 3),
        "unique_ratio": round(unique_ratio, 3),
        "repeated_prompts_ratio": round(repeated, 3),
        "suspicious": suspicious,
        "risk_level": "high" if suspicious else "low",
        "explanation": "Patterns répétitifs / entropie élevée → possible tentative d'extraction de modèle" if suspicious else "Activité normale détectée"
    }
    click.echo(json.dumps(result, indent=2))
    if suspicious:
        click.secho("⚠️ Activité suspecte – possible fingerprinting / model stealing", fg="red", bold=True)

@cli.command(name="detect-poisoning")
@click.argument("log_file", type=click.Path(exists=True, path_type=Path))
def detect_poisoning(log_file: Path):
    data = json.loads(log_file.read_text(encoding="utf-8", errors="replace"))
    result = analyze_poisoning_from_logs(data)
    result["engine"] = "poisoning-detector"
    click.echo(json.dumps(result, indent=2))

    if result.get("poisoning_detected"):
        click.secho(
            "⚠️ Data poisoning ou model extraction suspectée",
            fg="red",
            bold=True
        )



if __name__ == "__main__":
    cli(obj={})
