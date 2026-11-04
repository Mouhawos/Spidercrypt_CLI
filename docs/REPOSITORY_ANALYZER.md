# Spidercrypt Repository Analyzer (MVP)

The first repository-scanning engine is available as a standalone Python module. It inventories a repository and performs conservative, syntax-aware checks on Python files.

## Run

    python -m spidercrypt_scanner .
    python -m spidercrypt_scanner /path/to/project --json spidercrypt-report.json

The command prints a JSON report. Its exit status is 1 when findings are present and 0 when no findings are reported.

## Initial checks
- Dynamic execution with eval() or exec()
- Unsafe pickle / dill deserialization
- yaml.load() without a safe loader
- tempfile.mktemp()
- Subprocess calls using shell=True
- HTTP requests with TLS verification disabled
- MD5 / SHA-1 usage
- Common hardcoded credential and private-key patterns

The scanner also reports Python file inventory, file extensions, and frameworks inferred from common dependency manifests.

## Safety and scope
- Reads source files but does not import or execute repository code.
- Skips symlinks and common generated/vendor directories.
- Skips Python files above 1 MB and caps analysis at 5,000 Python files.
- Findings are indicators, not proof of exploitability. Review context before treating them as confirmed vulnerabilities.
- Python only. No taint analysis, dependency vulnerability matching, secret-provider verification, or AI remediation yet.

## Tests

    pip install pytest
    pytest tests/test_repository_analyzer.py -q
