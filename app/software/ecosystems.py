"""Map normalized products to package ecosystems and upstream version sources."""

from __future__ import annotations

import re

# canonical_id -> upstream metadata for authoritative latest-version lookup
_UPSTREAM: dict[str, dict[str, str]] = {
    "nginx.nginx": {"source": "github", "repo": "nginx/nginx", "ecosystem": "GitHub"},
    "openssl.openssl": {"source": "github", "repo": "openssl/openssl", "ecosystem": "GitHub"},
    "apache.httpd": {"source": "github", "repo": "apache/httpd", "ecosystem": "GitHub"},
    "openbsd.openssh": {"source": "github", "repo": "openssh/openssh-portable", "ecosystem": "GitHub"},
    "postgresql.postgresql": {"source": "github", "repo": "postgres/postgres", "ecosystem": "GitHub"},
    "python.python": {"source": "endoflife", "product": "python", "ecosystem": "Python"},
    "openjs.nodejs": {"source": "endoflife", "product": "nodejs", "ecosystem": "Node.js"},
    "mozilla.firefox": {"source": "endoflife", "product": "firefox", "ecosystem": "Firefox"},
    "google.chrome": {"source": "endoflife", "product": "chrome", "ecosystem": "Chrome"},
    "microsoft.edge": {"source": "endoflife", "product": "edge", "ecosystem": "Edge"},
    "oracle.mysql": {"source": "github", "repo": "mysql/mysql-server", "ecosystem": "GitHub"},
    "mariadb.mariadb": {"source": "github", "repo": "MariaDB/server", "ecosystem": "GitHub"},
    "videolan.vlc": {"source": "github", "repo": "videolan/vlc", "ecosystem": "GitHub"},
    "git.git": {"source": "github", "repo": "git/git", "ecosystem": "GitHub"},
    "docker.docker": {"source": "github", "repo": "moby/moby", "ecosystem": "GitHub"},
}

# Normalized name hints for PyPI/npm when canonical_id is generic
_PYPI_HINTS = frozenset({"semgrep", "pip", "ansible", "django", "flask", "requests"})
_NPM_HINTS = frozenset({"express", "lodash", "react", "next", "axios"})

# Product-name patterns → upstream (Windows Control Panel / agent inventory)
_NAME_PATTERNS: list[tuple[re.Pattern[str], dict[str, str]]] = [
    (re.compile(r"^node\.?js\b", re.I), {"source": "endoflife", "product": "nodejs", "ecosystem": "Node.js"}),
    (re.compile(r"^python\b", re.I), {"source": "endoflife", "product": "python", "ecosystem": "Python"}),
    (re.compile(r"^vlc\b", re.I), {"source": "github", "repo": "videolan/vlc", "ecosystem": "GitHub"}),
    (re.compile(r"^git\b", re.I), {"source": "github", "repo": "git/git", "ecosystem": "GitHub"}),
    (re.compile(r"^docker\b", re.I), {"source": "github", "repo": "moby/moby", "ecosystem": "GitHub"}),
    (re.compile(r"^mozilla firefox|^firefox\b", re.I), {"source": "endoflife", "product": "firefox", "ecosystem": "Firefox"}),
    (re.compile(r"^google chrome|^chrome\b", re.I), {"source": "endoflife", "product": "chrome", "ecosystem": "Chrome"}),
    (re.compile(r"^microsoft edge|^edge\b", re.I), {"source": "endoflife", "product": "edge", "ecosystem": "Edge"}),
    (re.compile(r"^nginx\b", re.I), {"source": "github", "repo": "nginx/nginx", "ecosystem": "GitHub"}),
    (re.compile(r"^openssl\b", re.I), {"source": "github", "repo": "openssl/openssl", "ecosystem": "GitHub"}),
    (re.compile(r"^postgresql\b|^postgres\b", re.I), {"source": "github", "repo": "postgres/postgres", "ecosystem": "GitHub"}),
    (re.compile(r"^openssh\b", re.I), {"source": "github", "repo": "openssh/openssh-portable", "ecosystem": "GitHub"}),
]


def upstream_for(canonical_id: str, name: str = "") -> dict[str, str]:
    cid = (canonical_id or "").strip().lower()
    if cid in _UPSTREAM:
        return dict(_UPSTREAM[cid])
    key = (name or "").strip().lower()
    key = re.sub(r"\s+", " ", key)
    if key in _PYPI_HINTS:
        return {"source": "pypi", "package": key, "ecosystem": "PyPI"}
    if key in _NPM_HINTS:
        return {"source": "npm", "package": key, "ecosystem": "npm"}
    for pat, meta in _NAME_PATTERNS:
        if pat.search(name or "") or pat.search(key):
            return dict(meta)
    return {}


def ecosystem_for(canonical_id: str, name: str = "", source: str = "") -> str:
    up = upstream_for(canonical_id, name)
    if up.get("ecosystem"):
        return str(up["ecosystem"])
    src = (source or "").lower()
    if src in {"scan", "vuln", "nmap", "nuclei", "zap"}:
        return "network"
    if src in {"wazuh", "siem"}:
        return "endpoint"
    if src in {"openaudit", "lan"}:
        return "inventory"
    if src in {"securaiq_agent", "agent", "control_panel"}:
        return "endpoint"
    return ""
