"""Import-to-distribution name resolution and Levenshtein typo-candidate checks."""

from __future__ import annotations

import re


def normalize_pkg(name: str) -> str:
    """Normalize a Python distribution name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


# Curated mapping from top-level Python import name (case-sensitive or lowercase)
# to candidate normalized PyPI distribution names.
KNOWN_IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "PIL": ("pillow", "pil"),
    "OpenSSL": ("pyopenssl",),
    "Crypto": ("pycryptodome", "pycrypto"),
    "Cryptodome": ("pycryptodomex", "pycryptodome"),
    "MySQLdb": ("mysqlclient", "mysql-python"),
    "Levenshtein": ("levenshtein", "python-levenshtein"),
    "yaml": ("pyyaml",),
    "bs4": ("beautifulsoup4", "bs4"),
    "cv2": ("opencv-python", "opencv-python-headless", "opencv-contrib-python", "opencv-contrib-python-headless"),
    "sklearn": ("scikit-learn",),
    "skimage": ("scikit-image",),
    "dotenv": ("python-dotenv",),
    "dateutil": ("python-dateutil",),
    "jwt": ("pyjwt", "jwt"),
    "git": ("gitpython",),
    "fitz": ("pymupdf",),
    "nacl": ("pynacl",),
    "attr": ("attrs", "attr"),
    "serial": ("pyserial",),
    "usb": ("pyusb",),
    "magic": ("python-magic", "python-magic-bin"),
    "websocket": ("websocket-client",),
    "dns": ("dnspython",),
    "psycopg2": ("psycopg2", "psycopg2-binary"),
    "psycopg": ("psycopg", "psycopg-binary"),
    "gi": ("pygobject",),
    "wx": ("wxpython",),
    "cairo": ("pycairo",),
    "jose": ("python-jose",),
    "multipart": ("python-multipart",),
    "slugify": ("python-slugify", "awesome-slugify"),
    "rapidjson": ("python-rapidjson",),
    "ruamel": ("ruamel-yaml",),
    "docx": ("python-docx",),
    "pptx": ("python-pptx",),
    "socks": ("pysocks",),
    "memcache": ("python-memcached",),
    "ldap": ("python-ldap",),
    "daemon": ("python-daemon",),
    "gnupg": ("python-gnupg",),
    "telegram": ("python-telegram-bot",),
    "discord": ("discord-py", "py-cord", "nextcord"),
    "graphql": ("graphql-core",),
    "graphene": ("graphene",),
    "prometheus_client": ("prometheus-client",),
    "sentry_sdk": ("sentry-sdk",),
    "pydantic_settings": ("pydantic-settings",),
    "typing_extensions": ("typing-extensions",),
    "importlib_metadata": ("importlib-metadata",),
    "importlib_resources": ("importlib-resources",),
}

# Dotted namespace prefixes mapped to normalized distribution names
DOTTED_IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "google.protobuf": ("protobuf",),
    "google.auth": ("google-auth",),
    "google.api_core": ("google-api-core",),
    "google.genai": ("google-genai",),
    "google.generativeai": ("google-generativeai",),
    "ruamel.yaml": ("ruamel-yaml",),
}

# Popular PyPI packages frequently targeted by typosquatting / LLM slopsquatting
POPULAR_ECOSYSTEM_PACKAGES: tuple[str, ...] = (
    "requests",
    "httpx",
    "urllib3",
    "aiohttp",
    "pydantic",
    "pydantic-settings",
    "fastapi",
    "starlette",
    "uvicorn",
    "gunicorn",
    "flask",
    "django",
    "sqlalchemy",
    "alembic",
    "psycopg2-binary",
    "asyncpg",
    "redis",
    "celery",
    "boto3",
    "botocore",
    "cryptography",
    "pynacl",
    "pyopenssl",
    "paramiko",
    "pyjwt",
    "bcrypt",
    "argon2-cffi",
    "numpy",
    "pandas",
    "polars",
    "scipy",
    "scikit-learn",
    "matplotlib",
    "torch",
    "transformers",
    "datasets",
    "huggingface-hub",
    "openai",
    "anthropic",
    "langchain",
    "langchain-core",
    "tiktoken",
    "pytest",
    "hypothesis",
    "coverage",
    "ruff",
    "mypy",
    "pylint",
    "black",
    "isort",
    "rich",
    "click",
    "typer",
    "jinja2",
    "markupsafe",
    "pyyaml",
    "tomlkit",
    "tomli",
    "tomli-w",
    "packaging",
    "tenacity",
    "structlog",
    "loguru",
    "beautifulsoup4",
    "lxml",
    "pillow",
    "python-dotenv",
    "python-dateutil",
    "attrs",
    "cattrs",
    "orjson",
    "ujson",
    "msgpack",
    "protobuf",
    "grpcio",
    "websockets",
    "networkx",
    "duckdb",
    "pyarrow",
)


def candidate_distributions(
    top_module: str,
    full_module: str,
    custom_aliases: dict[str, str] | None = None,
) -> set[str]:
    """Return all plausible normalized PyPI distribution names for an imported module."""
    candidates: set[str] = {normalize_pkg(top_module)}

    if custom_aliases:
        if full_module in custom_aliases:
            candidates.add(normalize_pkg(custom_aliases[full_module]))
        if top_module in custom_aliases:
            candidates.add(normalize_pkg(custom_aliases[top_module]))

    for prefix, dists in DOTTED_IMPORT_ALIASES.items():
        if full_module == prefix or full_module.startswith(prefix + "."):
            candidates.update(dists)

    if full_module.startswith("google.cloud."):
        parts = full_module.split(".")
        if len(parts) >= 3:
            candidates.add(normalize_pkg(f"google-cloud-{parts[2]}"))

    if top_module in KNOWN_IMPORT_ALIASES:
        candidates.update(KNOWN_IMPORT_ALIASES[top_module])

    return candidates


def levenshtein_bounded(a: str, b: str, max_dist: int = 2) -> int:
    """Compute exact Levenshtein edit distance, returning max_dist + 1 if exceeded."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    if len(a) > len(b):
        a, b = b, a

    prev = list(range(len(a) + 1))
    for j, cb in enumerate(b, start=1):
        curr = [j]
        row_min = j
        for i, ca in enumerate(a, start=1):
            cost = 0 if ca == cb else 1
            val = min(
                prev[i] + 1,       # deletion
                curr[i - 1] + 1,   # insertion
                prev[i - 1] + cost # substitution
            )
            curr.append(val)
            if val < row_min:
                row_min = val
        if row_min > max_dist:
            return max_dist + 1
        prev = curr
    return prev[-1]


def find_typo_matches(
    import_name: str,
    repo_packages: set[str],
    max_dist: int = 2,
) -> list[str]:
    """Find close Levenshtein matches against repo packages and popular PyPI packages."""
    norm = normalize_pkg(import_name)
    if len(norm) < 4:
        return []

    max_allowed = 1 if len(norm) <= 5 else max_dist
    pool = set(POPULAR_ECOSYSTEM_PACKAGES) | repo_packages
    scored: list[tuple[int, str]] = []
    for target in pool:
        if target == norm:
            continue
        dist = levenshtein_bounded(norm, target, max_dist=max_allowed)
        if dist <= max_allowed:
            scored.append((dist, target))

    scored.sort(key=lambda item: (item[0], item[1]))
    return [name for _, name in scored[:3]]
