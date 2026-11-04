import ast

from spidercrypt_scanner.analyzer import _PythonVisitor, analyze_repository


def test_detects_dynamic_execution_and_pickle():
    source = "eval(user_input)\npickle.loads(payload)\n"
    visitor = _PythonVisitor(source, "sample.py")
    visitor.visit(ast.parse(source))
    assert {item["rule_id"] for item in visitor.findings} == {
        "SPC.PY.001", "SPC.PY.002"
    }


def test_detects_shell_true():
    source = 'subprocess.run(command, shell=True)\n'
    visitor = _PythonVisitor(source, "sample.py")
    visitor.visit(ast.parse(source))
    assert visitor.findings[0]["rule_id"] == "SPC.PY.005"
    assert visitor.findings[0]["line"] == 1


def test_repository_inventory_and_report(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi==0.115\n")
    (tmp_path / "app.py").write_text("eval(input())\n")
    report = analyze_repository(tmp_path)
    assert report["inventory"]["python_files_analyzed"] == 1
    assert "FastAPI" in report["inventory"]["frameworks_detected"]
    assert report["findings"][0]["rule_id"] == "SPC.PY.001"
