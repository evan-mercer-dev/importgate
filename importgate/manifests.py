"""Parsers for pyproject.toml, requirements*.txt, uv.lock, and poetry.lock."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import tomllib

from .aliases import normalize_pkg

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")


@dataclass
class ManifestInventory:
    """Declared and locked dependency sets discovered in a repository."""

    runtime_deps: set[str] = field(default_factory=set)
    dev_or_optional_deps: set[str] = field(default_factory=set)
    locked_deps: set[str] = field(default_factory=set)
    manifest_files: list[str] = field(default_factory=list)
    lock_files: list[str] = field(default_factory=list)
    custom_aliases: dict[str, str] = field(default_factory=dict)
    ignored_imports: set[str] = field(default_factory=set)
    extra_source_roots: list[str] = field(default_factory=list)
    project_name: str | None = None

    @property
    def all_direct_deps(self) -> set[str]:
        return self.runtime_deps | self.dev_or_optional_deps

    @property
    def transitive_only_deps(self) -> set[str]:
        excluded = self.all_direct_deps
        if self.project_name:
            excluded = excluded | {self.project_name}
        return self.locked_deps - excluded


def extract_req_name(spec: str) -> str | None:
    """Extract normalized package name from a PEP 508 or pip requirement line."""
    line = spec.strip()
    if not line or line.startswith("#"):
        return None
    # Remove inline comment
    if " #" in line:
        line = line.split(" #", 1)[0].strip()
    # Skip pip flags / includes / editable local paths
    if line.startswith(("-", ".", "/", "http://", "https://", "git+")):
        if "#egg=" in line:
            egg = line.split("#egg=", 1)[1].split("&", 1)[0]
            return normalize_pkg(egg)
        return None
    # Strip environment markers
    if ";" in line:
        line = line.split(";", 1)[0].strip()
    m = _REQ_NAME_RE.match(line)
    if not m:
        return None
    return normalize_pkg(m.group(1))


def _parse_pyproject(pyproject_path: Path, inv: ManifestInventory) -> None:
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    inv.manifest_files.append(pyproject_path.name)

    project = data.get("project", {})
    if isinstance(project, dict):
        if isinstance(project.get("name"), str):
            inv.project_name = normalize_pkg(project["name"])
        for req in project.get("dependencies", []) or []:
            if isinstance(req, str):
                pkg = extract_req_name(req)
                if pkg:
                    inv.runtime_deps.add(pkg)
        opt_deps = project.get("optional-dependencies", {})
        if isinstance(opt_deps, dict):
            for group_reqs in opt_deps.values():
                if isinstance(group_reqs, list):
                    for req in group_reqs:
                        if isinstance(req, str):
                            pkg = extract_req_name(req)
                            if pkg:
                                inv.dev_or_optional_deps.add(pkg)

    # PEP 735 dependency-groups
    dep_groups = data.get("dependency-groups", {})
    if isinstance(dep_groups, dict):
        for group_items in dep_groups.values():
            if isinstance(group_items, list):
                for item in group_items:
                    if isinstance(item, str):
                        pkg = extract_req_name(item)
                        if pkg:
                            inv.dev_or_optional_deps.add(pkg)

    # Poetry support
    tool = data.get("tool", {})
    if isinstance(tool, dict):
        poetry = tool.get("poetry", {})
        if isinstance(poetry, dict):
            if not inv.project_name and isinstance(poetry.get("name"), str):
                inv.project_name = normalize_pkg(poetry["name"])
            p_deps = poetry.get("dependencies", {})
            if isinstance(p_deps, dict):
                for k, v in p_deps.items():
                    if k.lower() == "python":
                        continue
                    if isinstance(v, dict) and v.get("optional") is True:
                        inv.dev_or_optional_deps.add(normalize_pkg(k))
                    else:
                        inv.runtime_deps.add(normalize_pkg(k))
            p_dev = poetry.get("dev-dependencies", {})
            if isinstance(p_dev, dict):
                for k in p_dev:
                    if k.lower() != "python":
                        inv.dev_or_optional_deps.add(normalize_pkg(k))
            p_groups = poetry.get("group", {})
            if isinstance(p_groups, dict):
                for gname, gdata in p_groups.items():
                    if isinstance(gdata, dict):
                        gdeps = gdata.get("dependencies", {})
                        if isinstance(gdeps, dict):
                            target = inv.runtime_deps if gname == "main" else inv.dev_or_optional_deps
                            for k in gdeps:
                                if k.lower() != "python":
                                    target.add(normalize_pkg(k))

        # [tool.importgate] configuration
        ig_cfg = tool.get("importgate", {})
        if isinstance(ig_cfg, dict):
            aliases = ig_cfg.get("aliases", {})
            if isinstance(aliases, dict):
                for mod_name, dist_name in aliases.items():
                    if isinstance(mod_name, str) and isinstance(dist_name, str):
                        inv.custom_aliases[mod_name] = normalize_pkg(dist_name)
            ignored = ig_cfg.get("ignore_imports", [])
            if isinstance(ignored, list):
                for mod_name in ignored:
                    if isinstance(mod_name, str):
                        inv.ignored_imports.add(mod_name)
            roots = ig_cfg.get("source_roots", [])
            if isinstance(roots, list):
                for r in roots:
                    if isinstance(r, str):
                        inv.extra_source_roots.append(r)


def _parse_requirements_txt(req_path: Path, is_dev: bool, inv: ManifestInventory, root: Path) -> None:
    rel = str(req_path.relative_to(root))
    inv.manifest_files.append(rel)
    target = inv.dev_or_optional_deps if is_dev else inv.runtime_deps

    raw_lines = req_path.read_text(encoding="utf-8", errors="replace").splitlines()
    joined: list[str] = []
    buf = ""
    for line in raw_lines:
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
        else:
            buf += stripped
            joined.append(buf)
            buf = ""
    if buf:
        joined.append(buf)

    for line in joined:
        # Remove --hash options
        cleaned = re.sub(r"--hash=\S+", "", line).strip()
        pkg = extract_req_name(cleaned)
        if pkg:
            target.add(pkg)


def _parse_toml_lockfile(lock_path: Path, inv: ManifestInventory) -> None:
    data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    inv.lock_files.append(lock_path.name)
    packages = data.get("package", [])
    if isinstance(packages, list):
        for entry in packages:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                inv.locked_deps.add(normalize_pkg(entry["name"]))


def load_inventory(root: Path) -> ManifestInventory:
    """Discover and parse all dependency manifests and lockfiles under `root`."""
    inv = ManifestInventory()

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        _parse_pyproject(pyproject, inv)

    # Discover requirements*.txt in root and requirements/ subdir
    req_candidates: list[Path] = sorted(root.glob("requirements*.txt"))
    req_dir = root / "requirements"
    if req_dir.is_dir():
        req_candidates.extend(sorted(req_dir.glob("*.txt")))

    for req_file in req_candidates:
        fname_lower = req_file.name.lower()
        is_dev = any(tok in fname_lower for tok in ("dev", "test", "lint", "doc", "ci"))
        _parse_requirements_txt(req_file, is_dev=is_dev, inv=inv, root=root)

    # Discover uv.lock and poetry.lock
    for lock_name in ("uv.lock", "poetry.lock"):
        lock_path = root / lock_name
        if lock_path.is_file():
            _parse_toml_lockfile(lock_path, inv)

    return inv
