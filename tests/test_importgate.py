"""Comprehensive unit tests for importgate."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from importgate.analyzer import (
    KIND_DEV_IN_PROD,
    KIND_PHANTOM,
    KIND_TYPO,
    KIND_UNDECLARED,
    scan_repository,
)
from importgate.cli import main


class ImportGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, rel: str, content: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_clean_repo_with_aliases_type_checking_and_optional_try(self) -> None:
        self._write(
            "pyproject.toml",
            """
[project]
name = "acme-service"
dependencies = [
    "PyYAML>=6.0",
    "Pillow>=10.0",
    "requests[socks]>=2.31; python_version >= '3.11'",
]
[dependency-groups]
dev = ["pytest>=8.0"]
""",
        )
        self._write("src/acme_service/__init__.py", "VALUE = 1\n")
        self._write(
            "src/acme_service/worker.py",
            """
from __future__ import annotations
import json
import os
from typing import TYPE_CHECKING
import yaml
from PIL import Image
import requests
from . import VALUE
import acme_service

if TYPE_CHECKING:
    import mypy_only_stub

try:
    import uvloop
except ImportError:
    uvloop = None
""",
        )
        self._write(
            "tests/util.py",
            "HELPER = True\n",
        )
        self._write(
            "tests/test_worker.py",
            """
import pytest
from acme_service import worker
from tests.util import HELPER
""",
        )

        report = scan_repository(self.root)
        self.assertEqual(report.findings, [])

        # Enabling --include-type-checking and --strict-optional surfaces both guarded imports
        strict_report = scan_repository(
            self.root,
            include_type_checking=True,
            strict_optional=True,
        )
        modules = {f.imported_module for f in strict_report.findings}
        self.assertEqual(modules, {"mypy_only_stub", "uvloop"})

    def test_detects_slopsquatting_typo_and_undeclared(self) -> None:
        self._write(
            "pyproject.toml",
            """
[project]
name = "demo"
dependencies = ["httpx>=0.27"]
""",
        )
        self._write(
            "demo/client.py",
            """
import reqeusts
import completely_imaginary_sdk_xyz
""",
        )
        report = scan_repository(self.root)
        by_mod = {f.imported_module: f for f in report.findings}
        self.assertIn("reqeusts", by_mod)
        self.assertEqual(by_mod["reqeusts"].kind, KIND_TYPO)
        self.assertIn("requests", by_mod["reqeusts"].suggestions)

        self.assertIn("completely_imaginary_sdk_xyz", by_mod)
        self.assertEqual(by_mod["completely_imaginary_sdk_xyz"].kind, KIND_UNDECLARED)

    def test_detects_phantom_transitive_from_uv_lock(self) -> None:
        self._write(
            "pyproject.toml",
            """
[project]
name = "api-gateway"
dependencies = ["httpx>=0.27"]
""",
        )
        # anyio and certifi are locked transitively by httpx, but not declared directly
        self._write(
            "uv.lock",
            """
version = 1

[[package]]
name = "api-gateway"
version = "0.1.0"

[[package]]
name = "httpx"
version = "0.27.2"

[[package]]
name = "anyio"
version = "4.6.0"

[[package]]
name = "certifi"
version = "2024.8.30"
""",
        )
        self._write(
            "api_gateway/transport.py",
            """
import httpx
import anyio
""",
        )
        report = scan_repository(self.root)
        self.assertEqual(len(report.findings), 1)
        f = report.findings[0]
        self.assertEqual(f.kind, KIND_PHANTOM)
        self.assertEqual(f.imported_module, "anyio")

    def test_detects_dev_dependency_imported_in_prod(self) -> None:
        self._write(
            "pyproject.toml",
            """
[project]
name = "billing"
dependencies = ["pydantic>=2.0"]

[project.optional-dependencies]
test = ["faker>=25.0"]
""",
        )
        self._write("billing/models.py", "import pydantic\nimport faker\n")
        self._write("tests/test_models.py", "import faker\n")

        report = scan_repository(self.root)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].kind, KIND_DEV_IN_PROD)
        self.assertEqual(report.findings[0].file_rel, "billing/models.py")

    def test_git_diff_mode_ignores_legacy_debt_and_flags_new_lines(self) -> None:
        subprocess.run(["git", "init", str(self.root)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Test"], check=True)

        self._write(
            "pyproject.toml",
            '[project]\nname = "legacy"\ndependencies = ["requests"]\n',
        )
        # Pre-existing undeclared import committed in baseline
        self._write("legacy/app.py", "import old_legacy_untracked_lib\n\ndef run():\n    return 1\n")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-m", "init"], check=True, capture_output=True)

        # Modify file in working tree adding a new typo import
        self._write(
            "legacy/app.py",
            "import old_legacy_untracked_lib\nimport pydantc\n\ndef run():\n    return 1\n",
        )

        # Full scan catches both
        full_report = scan_repository(self.root)
        self.assertEqual(len(full_report.findings), 2)

        # Diff scan against HEAD catches ONLY the newly added `pydantc` import
        diff_report = scan_repository(self.root, diff_ref="HEAD")
        self.assertEqual(len(diff_report.findings), 1)
        self.assertEqual(diff_report.findings[0].imported_module, "pydantc")
        self.assertEqual(diff_report.findings[0].kind, KIND_TYPO)

    def test_cli_json_and_sarif_outputs_and_exit_codes(self) -> None:
        self._write("pyproject.toml", '[project]\nname = "svc"\ndependencies = []\n')
        self._write("svc/main.py", "import reqeusts\n")

        buf_json = io.StringIO()
        with contextlib.redirect_stdout(buf_json):
            rc = main([str(self.root), "--format", "json"])
        self.assertEqual(rc, 1)
        parsed_json = json.loads(buf_json.getvalue())
        self.assertEqual(len(parsed_json["findings"]), 1)
        self.assertEqual(parsed_json["findings"][0]["kind"], KIND_TYPO)

        # Non-blocking when --fail-on=none
        buf_sarif = io.StringIO()
        with contextlib.redirect_stdout(buf_sarif):
            rc_warn = main([str(self.root), "--format", "sarif", "--fail-on", "none"])
        self.assertEqual(rc_warn, 0)
        parsed_sarif = json.loads(buf_sarif.getvalue())
        self.assertEqual(parsed_sarif["version"], "2.1.0")
        self.assertEqual(len(parsed_sarif["runs"][0]["results"]), 1)

    def test_poetry_and_custom_alias_support(self) -> None:
        self._write(
            "pyproject.toml",
            """
[tool.poetry]
name = "poetry-svc"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
internal-company-bus = "^1.2.0"

[tool.importgate.aliases]
company_bus = "internal-company-bus"
""",
        )
        self._write("poetry_svc/handler.py", "import company_bus\n")
        report = scan_repository(self.root)
        self.assertEqual(report.findings, [])


if __name__ == "__main__":
    unittest.main()
