"""Finding (vulnerability) domain service — canonical security finding store."""

from app.enterprise import (
    create_vulnerability,
    delete_vulnerability,
    get_vulnerability,
    import_vulnerabilities,
    list_vulnerabilities,
    triage_vulnerability,
    update_vulnerability,
)

# Gradual vocabulary: Finding == Vulnerability row
create_finding = create_vulnerability
get_finding = get_vulnerability
list_findings = list_vulnerabilities
update_finding = update_vulnerability
delete_finding = delete_vulnerability
triage_finding = triage_vulnerability
import_findings = import_vulnerabilities

__all__ = [
    "create_finding",
    "create_vulnerability",
    "delete_finding",
    "delete_vulnerability",
    "get_finding",
    "get_vulnerability",
    "import_findings",
    "import_vulnerabilities",
    "list_findings",
    "list_vulnerabilities",
    "triage_finding",
    "triage_vulnerability",
    "update_finding",
    "update_vulnerability",
]
