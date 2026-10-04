"""Production code must not import app/dev/.

The production Dockerfile deletes app/dev/, so an import from it works in
development and tests but fails in every self-hosted install.
"""

import ast
from pathlib import Path

APP_DIR = Path(__file__).parent.parent / "app"


def _imports_dev(tree: ast.AST) -> list[int]:
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        elif isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        else:
            continue
        if any(name == "dev" or name.startswith("dev.") for name in names):
            lines.append(node.lineno)
    return lines


def test_production_code_does_not_import_dev():
    offenders = []
    for path in APP_DIR.rglob("*.py"):
        rel = path.relative_to(APP_DIR)
        if rel.parts[0] == "dev":
            continue
        for line in _imports_dev(ast.parse(path.read_text(), filename=str(path))):
            offenders.append(f"app/{rel}:{line}")

    assert offenders == [], f"Production modules import app/dev/: {offenders}"
