"""Repository inventory and conservative Python security analysis.

This module never imports or executes scanned project code.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__",
    "node_modules", "dist", "build", ".mypy_cache", ".pytest_cache",
    ".tox", ".nox", ".idea", ".vscode",
}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 5_000

SECRET_PATTERNS = [
    ("SPC.SECRET.001", re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"), "Possible AWS access key"),
    ("SPC.SECRET.002", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key material"),
    ("SPC.SECRET.003", re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|password|passwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "Possible hardcoded credential"),
]

def _finding(rule_id: str, title: str, severity: str, path: str,
             line: int, evidence: str, recommendation: str,
             confidence: str = "medium") -> dict[str, Any]:
    return {
        "rule_id": rule_id, "title": title, "severity": severity,
        "confidence": confidence, "path": path, "line": line,
        "evidence": evidence[:240], "recommendation": recommendation,
    }

class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, source: str, relative_path: str):
        self.source = source
        self.path = relative_path
        self.lines = source.splitlines()
        self.findings: list[dict[str, Any]] = []

    def add(self, node: ast.AST, rule: str, title: str, severity: str,
            recommendation: str, confidence: str = "medium") -> None:
        line = getattr(node, "lineno", 1)
        evidence = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings.append(_finding(
            rule, title, severity, self.path, line, evidence,
            recommendation, confidence,
        ))

    @staticmethod
    def call_name(node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            base = _PythonVisitor.call_name(ast.Call(func=func.value, args=[], keywords=[])) if isinstance(func.value, ast.Call) else ""
            if isinstance(func.value, ast.Name):
                base = func.value.id
            return f"{base}.{func.attr}" if base else func.attr
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        name = self.call_name(node)
        if name in {"eval", "exec"}:
            self.add(node, "SPC.PY.001", f"Dynamic code execution via {name}()", "high",
                     "Avoid evaluating untrusted strings; use a constrained parser or explicit dispatch.", "high")
        elif name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads"}:
            self.add(node, "SPC.PY.002", "Unsafe object deserialization", "high",
                     "Do not deserialize untrusted data with pickle/dill; use a safe data format.", "high")
        elif name == "yaml.load":
            safe_loader = any(k.arg == "Loader" and isinstance(k.value, ast.Attribute)
                              and k.value.attr in {"SafeLoader", "CSafeLoader"} for k in node.keywords)
            if not safe_loader:
                self.add(node, "SPC.PY.003", "Potentially unsafe YAML deserialization", "high",
                         "Use yaml.safe_load() or explicitly use yaml.SafeLoader.", "high")
        elif name == "tempfile.mktemp":
            self.add(node, "SPC.PY.004", "Insecure temporary-file name generation", "medium",
                     "Use tempfile.mkstemp() or NamedTemporaryFile() to avoid race conditions.", "high")
        elif name in {"subprocess.run", "subprocess.call", "subprocess.Popen"}:
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                             and k.value.value is True for k in node.keywords)
            if shell_true:
                self.add(node, "SPC.PY.005", "Subprocess invoked with shell=True", "high",
                         "Pass an argument list with shell=False; validate any externally controlled arguments.", "high")
        elif name in {"requests.get", "requests.post", "requests.put", "requests.request"}:
            verify_false = any(k.arg == "verify" and isinstance(k.value, ast.Constant)
                               and k.value.value is False for k in node.keywords)
            if verify_false:
                self.add(node, "SPC.PY.006", "TLS certificate verification disabled", "high",
                         "Remove verify=False and configure a trusted CA bundle if necessary.", "high")
        elif name in {"hashlib.md5", "hashlib.sha1"}:
            self.add(node, "SPC.PY.007", "Weak cryptographic hash", "low",
                     "Use SHA-256 or a modern password-hashing algorithm, depending on the use case.", "high")
        self.generic_visit(node)

def _detect_frameworks(root: Path) -> list[str]:
    found: set[str] = set()
    for name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for package, framework in (
            ("fastapi", "FastAPI"), ("django", "Django"), ("flask", "Flask"),
            ("sqlalchemy", "SQLAlchemy"), ("celery", "Celery"),
            ("pytest", "pytest"), ("torch", "PyTorch"),
        ):
            if package in text:
                found.add(framework)
    return sorted(found)

def analyze_repository(repository: str | Path) -> dict[str, Any]:
    root = Path(repository).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")

    findings: list[dict[str, Any]] = []
    languages: dict[str, int] = {}
    files_analyzed = 0
    skipped_large = 0
    parse_errors = 0

    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix:
            languages[suffix] = languages.get(suffix, 0) + 1
        if suffix != ".py":
            continue
        if files_analyzed >= MAX_FILES:
            break
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped_large += 1
                continue
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue

        files_analyzed += 1
        relative = path.relative_to(root).as_posix()
        for rule_id, pattern, title in SECRET_PATTERNS:
            for match in pattern.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                findings.append(_finding(
                    rule_id, title, "critical" if "PRIVATE" in title else "high",
                    relative, line, source.splitlines()[line - 1].strip(),
                    "Remove the secret from source control, rotate it, and load it from a secret manager.",
                    "medium",
                ))
        try:
            tree = ast.parse(source, filename=relative)
        except SyntaxError:
            parse_errors += 1
            continue
        visitor = _PythonVisitor(source, relative)
        visitor.visit(tree)
        findings.extend(visitor.findings)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (severity_order.get(item["severity"], 9), item["path"], item["line"]))
    counts = {level: sum(f["severity"] == level for f in findings)
              for level in ("critical", "high", "medium", "low")}
    return {
        "schema_version": "1.0",
        "scanner": "Spidercrypt Repository Analyzer",
        "repository": root.name,
        "root": str(root),
        "inventory": {
            "python_files_analyzed": files_analyzed,
            "files_by_extension": dict(sorted(languages.items())),
            "frameworks_detected": _detect_frameworks(root),
            "large_files_skipped": skipped_large,
            "python_parse_errors": parse_errors,
        },
        "summary": {"findings": len(findings), "by_severity": counts},
        "findings": findings,
        "limitations": [
            "Initial scanner analyzes Python source only.",
            "Findings are static indicators and require contextual review.",
            "No project code is imported or executed.",
            "This MVP does not perform interprocedural taint analysis or prove exploitability.",
        ],
    }

def report_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)
