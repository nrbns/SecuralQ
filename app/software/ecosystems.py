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
    "python.python": {"source": "pypi", "package": "pip", "ecosystem": "PyPI"},
    "openjs.nodejs": {"source": "github", "repo": "nodejs/node", "ecosystem": "GitHub"},
    "mozilla.firefox": {"source": "github", "repo": "mozilla/gecko-dev", "ecosystem": "GitHub"},
    "google.chrome": {"source": "vendor", "ecosystem": "vendor"},
    "microsoft.edge": {"source": "vendor", "ecosystem": "vendor"},
    "oracle.mysql": {"source": "github", "repo": "mysql/mysql-server", "ecosystem": "GitHub"},
    "mariadb.mariadb": {"source": "github", "repo": "MariaDB/server", "ecosystem": "GitHub"},
}

# Normalized name hints for PyPI/npm when canonical_id is generic
_PYPI_HINTS = frozenset({"semgrep", "pip", "ansible", "django", "flask", "requests"})
_NPM_HINTS = frozenset({"express", "lodash", "react", "next", "axios"})


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
    return ""
