"""Command-line interface and text/JSON/SARIF formatters for importgate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .analyzer import (
    KIND_DEV_IN_PROD,
    KIND_PHANTOM,
    KIND_TYPO,
    KIND_UNDECLARED,
    Finding,
    ScanReport,
    scan_repository,
)

_RULE_FLAG_MAP = {
    "typo": KIND_TYPO,
    "undeclared": KIND_UNDECLARED,
    "phantom": KIND_PHANTOM,
    "dev-in-prod": KIND_DEV_IN_PROD,
}

_SARIF_LEVEL = {
    KIND_TYPO: "error",
    KIND_UNDECLARED: "error",
    KIND_PHANTOM: "warning",
    KIND_DEV_IN_PROD: "warning",
}


def format_text(report: ScanReport, fail_kinds: set[str]) -> str:
    lines: list[str] = []
    manifests = ", ".join(report.inventory.manifest_files) or "none"
    locks = ", ".join(report.inventory.lock_files) or "none"
    lines.append(
        f"importgate v{__version__} | scanned {report.files_scanned} files "
        f"({report.imports_inspected} imports) | manifests: {manifests} | lockfiles: {locks}"
    )

    if not report.findings:
        lines.append("OK: 0 dependency boundary findings.")
        return "\n".join(lines)

    lines.append("-" * 88)
    for f in report.findings:
        blocking = "FAIL" if f.kind in fail_kinds else "WARN"
        loc = f"{f.file_rel}:{f.lineno}:{f.col_offset + 1}"
        lines.append(f"[{blocking}] {f.kind:<18} {loc:<36} {f.message}")
    lines.append("-" * 88)

    counts: dict[str, int] = {}
    for f in report.findings:
        counts[f.kind] = counts.get(f.kind, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    lines.append(f"Total findings: {len(report.findings)} ({summary})")
    return "\n".join(lines)


def format_json(report: ScanReport) -> str:
    payload = {
        "version": __version__,
        "files_scanned": report.files_scanned,
        "imports_inspected": report.imports_inspected,
        "manifests": report.inventory.manifest_files,
        "lockfiles": report.inventory.lock_files,
        "findings": [f.to_dict() for f in report.findings],
    }
    return json.dumps(payload, indent=2)


def format_sarif(report: ScanReport) -> str:
    rules = [
        {
            "id": KIND_TYPO,
            "shortDescription": {"text": "Undeclared import close to known PyPI package (typosquatting/slopsquatting)"},
        },
        {
            "id": KIND_UNDECLARED,
            "shortDescription": {"text": "Undeclared third-party import missing from manifests"},
        },
        {
            "id": KIND_PHANTOM,
            "shortDescription": {"text": "Phantom transitive dependency imported directly without manifest declaration"},
        },
        {
            "id": KIND_DEV_IN_PROD,
            "shortDescription": {"text": "Dev/optional dependency imported in production module"},
        },
    ]

    results = []
    for f in report.findings:
        results.append({
            "ruleId": f.kind,
            "level": _SARIF_LEVEL.get(f.kind, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_rel},
                        "region": {
                            "startLine": f.lineno,
                            "startColumn": f.col_offset + 1,
                        },
                    }
                }
            ],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "importgate",
                        "version": __version__,
                        "informationUri": "https://github.com/evan-mercer-dev/importgate",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="importgate",
        description=(
            "Zero-dependency Python AST checker for undeclared imports, "
            "phantom transitive dependencies, and slopsquatting typo-candidates."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository root directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--diff",
        metavar="GIT_REF",
        default=None,
        help="Only check import lines added since GIT_REF (e.g. origin/main or HEAD~1).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--fail-on",
        default="typo,undeclared,phantom,dev-in-prod",
        help="Comma-separated finding categories that return exit code 1 (default: all).",
    )
    parser.add_argument(
        "--include-type-checking",
        action="store_true",
        help="Also enforce manifest rules on imports inside `if TYPE_CHECKING:` blocks.",
    )
    parser.add_argument(
        "--strict-optional",
        action="store_true",
        help="Also enforce manifest rules on imports wrapped in `try ... except ImportError:`.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"importgate {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        print(f"error: path '{args.path}' is not a directory", file=sys.stderr)
        return 2

    fail_kinds: set[str] = set()
    for token in (t.strip().lower() for t in args.fail_on.split(",") if t.strip()):
        if token == "none":
            continue
        if token not in _RULE_FLAG_MAP:
            print(
                f"error: unknown --fail-on category '{token}' "
                f"(valid: {', '.join(_RULE_FLAG_MAP)}, none)",
                file=sys.stderr,
            )
            return 2
        fail_kinds.add(_RULE_FLAG_MAP[token])

    try:
        report = scan_repository(
            root,
            diff_ref=args.diff,
            include_type_checking=args.include_type_checking,
            strict_optional=args.strict_optional,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(format_json(report))
    elif args.format == "sarif":
        print(format_sarif(report))
    else:
        print(format_text(report, fail_kinds))

    has_blocking = any(Finding.kind in fail_kinds for Finding in report.findings)
    return 1 if has_blocking else 0
