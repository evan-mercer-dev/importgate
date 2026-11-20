# importgate

Zero-dependency Python AST checker for **dependency boundaries**, **phantom transitive imports**, and **slopsquatting / typosquatting candidates** in pull requests.

Built exclusively on the Python 3.11+ standard library (`ast`, `tomllib`, `sys.stdlib_module_names`). Runs completely offline in milliseconds without importing or executing untrusted project code.

## Why `importgate`?

When commit velocity increases (especially across repositories using AI coding assistants or multi-team monorepos), dependency drift slips past code review in four recurring ways:

1. **`TYPO_CANDIDATE` (Slopsquatting / Typosquatting)**: Code imports an undeclared module within Levenshtein edit distance `<= 2` of a popular PyPI package or existing repo dependency (`import reqeusts`, `import pydantc`). If a developer or CI script naively `pip install`s the missing name, it creates a direct supply-chain foothold.
2. **`UNDECLARED_MISSING`**: Code imports a third-party module absent from `pyproject.toml` and `requirements*.txt` (hallucinated SDKs or forgotten manifest updates that pass local virtualenvs with stale packages installed).
3. **`PHANTOM_TRANSITIVE`**: Code directly `import`s a package (for example `anyio` or `certifi`) that only exists in `uv.lock` or `poetry.lock` as an indirect dependency of `httpx`. When `httpx` drops or swaps that transitive package in a minor bump, production breaks.
4. **`DEV_ONLY_IN_PROD`**: Production source modules outside `tests/` import packages declared solely in `[dependency-groups]`, `[project.optional-dependencies]`, or `requirements-dev.txt`.

### Low False-Positive AST Context Awareness

Unlike regex scanners, `importgate` walks the Python AST with structural context:
- Skips Python standard library modules (`sys.stdlib_module_names`).
- Resolves first-party modules across flat layouts, `src/` layouts, relative imports, and sibling scripts.
- Ignores type-only imports guarded under `if TYPE_CHECKING:` (unless `--include-type-checking` is passed).
- Ignores intentional optional runtime dependencies wrapped inside `try: ... except ImportError:` / `ModuleNotFoundError:` (unless `--strict-optional` is passed).
- Maps 50+ well-known import-to-distribution aliases (`yaml` -> `pyyaml`, `PIL` -> `pillow`, `cv2` -> `opencv-python`, `bs4` -> `beautifulsoup4`, `sklearn` -> `scikit-learn`, `google.cloud.*`, etc.) plus custom `[tool.importgate.aliases]`.

## Quick Start

```bash
git clone https://github.com/evan-mercer-dev/importgate.git
python3 -m pip install -e ./importgate

# Scan an entire repository
importgate /path/to/repo

# PR / CI Diff Gate: inspect ONLY imports added since origin/main
importgate /path/to/repo --diff origin/main

# Emit SARIF 2.1.0 for GitHub Code Scanning inline annotations
importgate /path/to/repo --diff origin/main --format sarif > results.sarif
```

You can also run it directly from source with zero installation:

```bash
PYTHONPATH=/path/to/importgate python3 -m importgate /path/to/repo
```

## Example Output

```text
importgate v0.1.0 | scanned 14 files (49 imports) | manifests: pyproject.toml | lockfiles: uv.lock
----------------------------------------------------------------------------------------
[FAIL] TYPO_CANDIDATE     api/client.py:4:1                    Undeclared import 'reqeusts' is within edit distance <=2 of known package(s): requests (potential typo or slopsquatting).
[FAIL] PHANTOM_TRANSITIVE api/transport.py:7:1                 Phantom transitive dependency: 'anyio' ('anyio') exists in uv.lock but is not declared in direct manifests.
[FAIL] DEV_ONLY_IN_PROD   api/seed.py:2:1                      Import 'faker' resolves to dev/optional dependency 'faker', which is not declared in runtime dependencies.
----------------------------------------------------------------------------------------
Total findings: 3 (DEV_ONLY_IN_PROD=1, PHANTOM_TRANSITIVE=1, TYPO_CANDIDATE=1)
```

## Configuration (`pyproject.toml`)

```toml
[tool.importgate]
ignore_imports = ["_custom_c_ext"]
source_roots = ["packages/shared/src"]

[tool.importgate.aliases]
company_bus = "acme-internal-bus"
```

## GitHub Actions Usage

```yaml
name: Dependency Boundary Gate
on: [pull_request]

jobs:
  importgate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/evan-mercer-dev/importgate.git
      - run: importgate . --diff origin/${{ github.base_ref }}
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
