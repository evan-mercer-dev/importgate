"""AST import boundary analyzer and Git diff line filter."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys

from .aliases import candidate_distributions, find_typo_matches, normalize_pkg
from .manifests import ManifestInventory, load_inventory

SKIP_DIRS: frozenset[str] = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    ".env",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".eggs",
})

NON_PROD_DIRS: frozenset[str] = frozenset({
    "tests",
    "test",
    "testing",
    "docs",
    "doc",
    "examples",
    "example",
    "benchmarks",
    "benchmark",
    "scripts",
    "devtools",
})

NON_PROD_FILENAMES: frozenset[str] = frozenset({
    "conftest.py",
    "noxfile.py",
    "fabfile.py",
    "tasks.py",
    "setup.py",
})

STDLIB_MODULES: frozenset[str] = frozenset(sys.stdlib_module_names) | {"__future__"}

KIND_TYPO = "TYPO_CANDIDATE"
KIND_UNDECLARED = "UNDECLARED_MISSING"
KIND_PHANTOM = "PHANTOM_TRANSITIVE"
KIND_DEV_IN_PROD = "DEV_ONLY_IN_PROD"


@dataclass(frozen=True)
class ImportOccurrence:
    """Single AST import statement location and context."""

    file_rel: str
    lineno: int
    col_offset: int
    top_module: str
    full_module: str
    in_type_checking: bool
    in_optional_try: bool
    is_non_prod_file: bool


@dataclass(frozen=True)
class Finding:
    """Policy finding emitted by importgate."""

    kind: str
    file_rel: str
    lineno: int
    col_offset: int
    imported_module: str
    message: str
    suggestions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "file": self.file_rel,
            "line": self.lineno,
            "column": self.col_offset + 1,
            "module": self.imported_module,
            "message": self.message,
            "suggestions": list(self.suggestions),
        }


def _is_type_checking_test(test: ast.expr) -> bool:
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
        return True
    if isinstance(test, ast.BoolOp):
        return any(_is_type_checking_test(v) for v in test.values)
    return False


def _catches_import_error(handlers: list[ast.ExceptHandler]) -> bool:
    import_err_names = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}

    def _matches(expr: ast.expr | None) -> bool:
        if expr is None:
            return True
        if isinstance(expr, ast.Name):
            return expr.id in import_err_names
        if isinstance(expr, ast.Tuple):
            return any(_matches(elt) for elt in expr.elts)
        return False

    return any(_matches(h.type) for h in handlers)


class _ImportVisitor(ast.NodeVisitor):
    def __init__(self, file_rel: str, is_non_prod_file: bool) -> None:
        self.file_rel = file_rel
        self.is_non_prod_file = is_non_prod_file
        self._type_checking_depth = 0
        self._optional_try_depth = 0
        self.occurrences: list[ImportOccurrence] = []

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking_test(node.test):
            self._type_checking_depth += 1
            for stmt in node.body:
                self.visit(stmt)
            self._type_checking_depth -= 1
            for stmt in node.orelse:
                self.visit(stmt)
        else:
            self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        guarded = _catches_import_error(node.handlers)
        if guarded:
            self._optional_try_depth += 1
        for stmt in node.body:
            self.visit(stmt)
        if guarded:
            self._optional_try_depth -= 1

        for handler in node.handlers:
            self.visit(handler)
        for stmt in node.orelse:
            self.visit(stmt)
        for stmt in node.finalbody:
            self.visit(stmt)

    visit_TryStar = visit_Try

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            full = alias.name
            top = full.split(".", 1)[0]
            self.occurrences.append(
                ImportOccurrence(
                    file_rel=self.file_rel,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    top_module=top,
                    full_module=full,
                    in_type_checking=self._type_checking_depth > 0,
                    in_optional_try=self._optional_try_depth > 0,
                    is_non_prod_file=self.is_non_prod_file,
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Relative imports (`from . import x` or `from ..sub import y`) are always first-party
        if node.level and node.level > 0:
            return
        if not node.module:
            return
        full = node.module
        top = full.split(".", 1)[0]
        self.occurrences.append(
            ImportOccurrence(
                file_rel=self.file_rel,
                lineno=node.lineno,
                col_offset=node.col_offset,
                top_module=top,
                full_module=full,
                in_type_checking=self._type_checking_depth > 0,
                in_optional_try=self._optional_try_depth > 0,
                is_non_prod_file=self.is_non_prod_file,
            )
        )


def discover_first_party_modules(root: Path, extra_roots: list[str] | None = None) -> set[str]:
    """Identify top-level first-party package and module names inside the repository."""
    first_party: set[str] = set()
    search_roots = [root, root / "src"]
    if extra_roots:
        for r in extra_roots:
            search_roots.append(root / r)

    for sroot in search_roots:
        if not sroot.is_dir():
            continue
        for child in sroot.iterdir():
            if child.name.startswith(".") or child.name in SKIP_DIRS or child.name.endswith(".egg-info"):
                continue
            if child.is_file() and child.suffix == ".py":
                first_party.add(child.stem)
            elif child.is_dir():
                if (child / "__init__.py").is_file() or any(child.glob("*.py")):
                    first_party.add(child.name)
    return first_party


def iter_python_files(root: Path) -> list[Path]:
    """Return sorted Python source files under `root`, pruning ignored directories."""
    results: list[Path] = []

    def _walk(curr: Path) -> None:
        try:
            entries = sorted(curr.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in SKIP_DIRS or entry.name.endswith(".egg-info"):
                    continue
                # Skip hidden dirs except root
                if entry.name.startswith("."):
                    continue
                _walk(entry)
            elif entry.is_file() and entry.suffix == ".py":
                results.append(entry)

    _walk(root)
    return results


def _is_non_prod_path(rel_parts: tuple[str, ...]) -> bool:
    if not rel_parts:
        return False
    fname = rel_parts[-1]
    if fname in NON_PROD_FILENAMES or fname.startswith("test_") or fname.endswith("_test.py"):
        return True
    return any(part in NON_PROD_DIRS for part in rel_parts[:-1])


def parse_git_diff_added_lines(root: Path, diff_ref: str) -> dict[str, set[int]]:
    """Run `git diff -U0 <diff_ref>` and return `{rel_path: {added_line_numbers}}`."""
    cmd = ["git", "-C", str(root), "diff", "--unified=0", diff_ref, "--", "*.py"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed ({proc.returncode}): {proc.stderr.strip()}")

    added: dict[str, set[int]] = {}
    current_file: str | None = None
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    for line in proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            added.setdefault(current_file, set())
        elif line.startswith("+++ /dev/null"):
            current_file = None
        elif current_file is not None and line.startswith("@@ "):
            m = hunk_re.match(line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                if count > 0:
                    added[current_file].update(range(start, start + count))
    return added


@dataclass
class ScanReport:
    """Full scan result including manifest inventory and findings."""

    inventory: ManifestInventory
    files_scanned: int
    imports_inspected: int
    findings: list[Finding]


def scan_repository(
    root: Path,
    *,
    diff_ref: str | None = None,
    include_type_checking: bool = False,
    strict_optional: bool = False,
) -> ScanReport:
    """Analyze Python AST imports in `root` against manifests and lockfiles."""
    root = root.resolve()
    inv = load_inventory(root)
    first_party = discover_first_party_modules(root, inv.extra_source_roots)
    if inv.project_name:
        first_party.add(inv.project_name.replace("-", "_"))

    diff_filter: dict[str, set[int]] | None = None
    if diff_ref:
        diff_filter = parse_git_diff_added_lines(root, diff_ref)

    py_files = iter_python_files(root)
    findings: list[Finding] = []
    total_imports = 0
    files_scanned = 0

    repo_pkg_pool = inv.all_direct_deps | inv.locked_deps

    for py_file in py_files:
        rel_path = py_file.relative_to(root)
        rel_posix = rel_path.as_posix()
        if diff_filter is not None and rel_posix not in diff_filter:
            continue

        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=rel_posix)
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue

        files_scanned += 1
        visitor = _ImportVisitor(rel_posix, is_non_prod_file=_is_non_prod_path(rel_path.parts))
        visitor.visit(tree)

        for occ in visitor.occurrences:
            if diff_filter is not None and occ.lineno not in diff_filter.get(rel_posix, set()):
                continue
            total_imports += 1

            if occ.in_type_checking and not include_type_checking:
                continue
            if occ.in_optional_try and not strict_optional:
                continue
            if occ.top_module in STDLIB_MODULES:
                continue
            if occ.top_module in inv.ignored_imports or occ.full_module in inv.ignored_imports:
                continue
            if occ.top_module in first_party:
                continue
            # Sibling module or package in the same directory
            if (py_file.parent / f"{occ.top_module}.py").is_file() or (py_file.parent / occ.top_module).is_dir():
                continue

            dists = candidate_distributions(occ.top_module, occ.full_module, inv.custom_aliases)

            # 1. Satisfied by runtime direct dependencies?
            if dists & inv.runtime_deps:
                continue

            # 2. Satisfied by dev/optional dependencies?
            if dists & inv.dev_or_optional_deps:
                if not occ.is_non_prod_file:
                    matched_dev = sorted(dists & inv.dev_or_optional_deps)[0]
                    findings.append(
                        Finding(
                            kind=KIND_DEV_IN_PROD,
                            file_rel=occ.file_rel,
                            lineno=occ.lineno,
                            col_offset=occ.col_offset,
                            imported_module=occ.full_module,
                            message=(
                                f"Import '{occ.full_module}' resolves to dev/optional dependency "
                                f"'{matched_dev}', which is not declared in runtime dependencies."
                            ),
                            suggestions=(matched_dev,),
                        )
                    )
                continue

            # 3. Present only as an indirect transitive package in lockfile?
            if dists & inv.transitive_only_deps:
                matched_trans = sorted(dists & inv.transitive_only_deps)[0]
                findings.append(
                    Finding(
                        kind=KIND_PHANTOM,
                        file_rel=occ.file_rel,
                        lineno=occ.lineno,
                        col_offset=occ.col_offset,
                        imported_module=occ.full_module,
                        message=(
                            f"Phantom transitive dependency: '{occ.full_module}' ('{matched_trans}') "
                            f"exists in {', '.join(inv.lock_files)} but is not declared in direct manifests."
                        ),
                        suggestions=(matched_trans,),
                    )
                )
                continue

            # 4. Completely undeclared — check if it looks like a typo / slopsquatting candidate
            typos = find_typo_matches(occ.top_module, repo_pkg_pool)
            if typos:
                findings.append(
                    Finding(
                        kind=KIND_TYPO,
                        file_rel=occ.file_rel,
                        lineno=occ.lineno,
                        col_offset=occ.col_offset,
                        imported_module=occ.full_module,
                        message=(
                            f"Undeclared import '{occ.top_module}' is within edit distance <=2 of "
                            f"known package(s): {', '.join(typos)} (potential typo or slopsquatting)."
                        ),
                        suggestions=tuple(typos),
                    )
                )
            else:
                norm_guess = normalize_pkg(occ.top_module)
                findings.append(
                    Finding(
                        kind=KIND_UNDECLARED,
                        file_rel=occ.file_rel,
                        lineno=occ.lineno,
                        col_offset=occ.col_offset,
                        imported_module=occ.full_module,
                        message=(
                            f"Undeclared third-party import '{occ.full_module}' is missing from "
                            f"repository dependency manifests ({', '.join(inv.manifest_files) or 'none found'})."
                        ),
                        suggestions=(norm_guess,),
                    )
                )

    return ScanReport(
        inventory=inv,
        files_scanned=files_scanned,
        imports_inspected=total_imports,
        findings=findings,
    )
