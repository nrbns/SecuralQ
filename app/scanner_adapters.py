"""Import adapters for mature open-source scanners.

SecuraIQ orchestrates findings — it does not replace the scanners.
Supported: Trivy, Semgrep, Gitleaks, Grype, Checkov, Bandit, SonarQube, SecuraIQ Web Scanner (ZAP export),
Burp Suite (Scanner XML export — Professional or Community "Save issues" report).
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any, Callable


def _sev_norm(sev: str, default: str = "medium") -> str:
    s = (sev or default).strip().upper()
    return {
        "CRITICAL": "critical",
        "BLOCKER": "critical",
        "HIGH": "high",
        "ERROR": "high",
        "MAJOR": "high",
        "MEDIUM": "medium",
        "WARNING": "medium",
        "MINOR": "low",
        "LOW": "low",
        "INFO": "info",
        "INFORMATIONAL": "info",
        "UNKNOWN": "info",
        "NEGLIGIBLE": "info",
        "NEGLLIGIBLE": "info",
    }.get(s, default if default in {"critical", "high", "medium", "low", "info"} else "medium")


def _sev_from_trivy(sev: str) -> str:
    return _sev_norm(sev, "medium")


def _sev_from_semgrep(sev: str) -> str:
    return _sev_norm(sev, "medium")


def _cvss_from_trivy(vuln: dict[str, Any]) -> float | None:
    """Trivy embeds per-source CVSS (nvd/redhat/ghsa/...) — prefer NVD V3, fall back to any V3/V2."""
    cvss_obj = vuln.get("CVSS")
    if not isinstance(cvss_obj, dict) or not cvss_obj:
        return None
    sources = list(cvss_obj.values())
    ordered = [cvss_obj.get("nvd")] if isinstance(cvss_obj.get("nvd"), dict) else []
    ordered += [s for s in sources if isinstance(s, dict) and s is not cvss_obj.get("nvd")]
    for src in ordered:
        score = src.get("V3Score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
    for src in ordered:
        score = src.get("V2Score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
    return None


def _cvss_from_grype(vuln: dict[str, Any]) -> float | None:
    """Grype's `vulnerability.cvss` is a list of {version, metrics: {baseScore}} — prefer highest CVSS version."""
    entries = vuln.get("cvss")
    if not isinstance(entries, list) or not entries:
        return None
    best = sorted(entries, key=lambda e: str(e.get("version") or ""), reverse=True)
    for entry in best:
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("metrics") or {}
        score = metrics.get("baseScore")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
    return None


def _sev_from_zap_risk(riskcode: str | int | None, riskdesc: str = "") -> str:
    try:
        code = int(riskcode) if riskcode is not None and str(riskcode).isdigit() else -1
    except (TypeError, ValueError):
        code = -1
    if code >= 3 or "high" in (riskdesc or "").lower():
        return "high"
    if code == 2 or "medium" in (riskdesc or "").lower():
        return "medium"
    if code == 1 or "low" in (riskdesc or "").lower():
        return "low"
    return "info"


def detect_scanner_format(data: Any, filename: str = "") -> str | None:
    """Return adapter name if payload matches a known scanner."""
    name = (filename or "").lower()
    hints = (
        ("trivy", "trivy"),
        ("semgrep", "semgrep"),
        ("gitleaks", "gitleaks"),
        ("secrets", "gitleaks"),
        ("grype", "grype"),
        ("checkov", "checkov"),
        ("bandit", "bandit"),
        ("sonar", "sonarqube"),
        ("zap", "zap"),
        ("zaproxy", "zap"),
    )
    for needle, kind in hints:
        if needle in name:
            return kind

    if isinstance(data, dict):
        if "Results" in data and isinstance(data.get("Results"), list):
            return "trivy"
        if isinstance(data.get("matches"), list):
            return "grype"
        if "results" in data and isinstance(data.get("results"), dict):
            res = data["results"]
            if isinstance(res.get("failed_checks"), list) or isinstance(res.get("passed_checks"), list):
                return "checkov"
        if isinstance(data.get("failed_checks"), list) and any(
            isinstance(x, dict) and ("check_id" in x or "check_name" in x) for x in (data.get("failed_checks") or [])[:3]
        ):
            return "checkov"
        if isinstance(data.get("issues"), list):
            sample = data["issues"][0] if data["issues"] else {}
            if isinstance(sample, dict) and ("component" in sample or "rule" in sample or "severity" in sample):
                return "sonarqube"
        if isinstance(data.get("site"), list):
            return "zap"
        if "results" in data and isinstance(data.get("results"), list):
            sample = data["results"][0] if data["results"] else {}
            if isinstance(sample, dict):
                if "issue_text" in sample or "issue_severity" in sample or "test_id" in sample:
                    return "bandit"
                if "check_id" in sample or "extra" in sample or ("path" in sample and "start" in sample):
                    return "semgrep"
        if isinstance(data.get("findings"), list):
            sample = data["findings"][0] if data["findings"] else {}
            if isinstance(sample, dict) and ("RuleID" in sample or "Secret" in sample or "Fingerprint" in sample):
                return "gitleaks"

    if isinstance(data, list) and data and isinstance(data[0], dict):
        row = data[0]
        if "RuleID" in row or "Secret" in row:
            return "gitleaks"
        if "check_id" in row and "path" in row:
            return "semgrep"
        if "issue_text" in row or "test_id" in row:
            return "bandit"
    return None


def parse_trivy(data: dict[str, Any], *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for result in data.get("Results") or []:
        target = result.get("Target") or result.get("TargetType") or ""
        for vuln in result.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID") or ""
            title = vuln.get("Title") or vuln.get("PkgName") or cve or "Trivy finding"
            pkg = vuln.get("PkgName") or ""
            if pkg and pkg not in title:
                title = f"{pkg}: {title}"
            items.append(
                {
                    "title": str(title)[:300],
                    "cve": str(cve)[:40],
                    "severity": _sev_from_trivy(str(vuln.get("Severity") or "MEDIUM")),
                    "asset_name": str(target)[:200],
                    "cvss": _cvss_from_trivy(vuln),
                    "engagement_id": engagement_id,
                    "source": f"trivy:{filename}",
                    "raw": vuln,
                }
            )
        for mis in result.get("Misconfigurations") or []:
            items.append(
                {
                    "title": str(mis.get("Title") or mis.get("ID") or "Misconfiguration")[:300],
                    "cve": str(mis.get("ID") or "")[:40],
                    "severity": _sev_from_trivy(str(mis.get("Severity") or "MEDIUM")),
                    "asset_name": str(target)[:200],
                    "cvss": None,
                    "engagement_id": engagement_id,
                    "source": f"trivy-misconfig:{filename}",
                    "raw": mis,
                }
            )
        for sec in result.get("Secrets") or []:
            items.append(
                {
                    "title": f"Secret: {sec.get('Title') or sec.get('RuleID') or 'detected'}"[:300],
                    "cve": "",
                    "severity": _sev_from_trivy(str(sec.get("Severity") or "HIGH")),
                    "asset_name": str(sec.get("Target") or target)[:200],
                    "cvss": None,
                    "engagement_id": engagement_id,
                    "source": f"trivy-secret:{filename}",
                    "raw": sec,
                }
            )
    return items


def parse_semgrep(data: dict[str, Any] | list, *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    rows = data.get("results") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        rows = []
    items: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        extra = row.get("extra") or {}
        meta = extra.get("metadata") or {}
        sev = extra.get("severity") or meta.get("severity") or "WARNING"
        path = row.get("path") or ""
        check = row.get("check_id") or meta.get("cwe") or "semgrep"
        msg = extra.get("message") or check
        items.append(
            {
                "title": str(msg)[:300],
                "cve": str(meta.get("cve") or meta.get("cwe") or "")[:40],
                "severity": _sev_from_semgrep(str(sev)),
                "asset_name": str(path)[:200],
                "cvss": None,
                "engagement_id": engagement_id,
                "source": f"semgrep:{filename}",
                "raw": row,
            }
        )
    return items


def parse_gitleaks(data: Any, *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        rows = data.get("findings") or data.get("leaks") or []
    elif isinstance(data, list):
        rows = data
    else:
        rows = []
    items: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rule = row.get("RuleID") or row.get("rule") or "secret"
        file_path = row.get("File") or row.get("file") or ""
        desc = row.get("Description") or row.get("description") or rule
        items.append(
            {
                "title": f"Secret leak: {desc}"[:300],
                "cve": "",
                "severity": "high",
                "asset_name": str(file_path)[:200],
                "cvss": None,
                "engagement_id": engagement_id,
                "source": f"gitleaks:{filename}",
                "raw": {k: v for k, v in row.items() if k.lower() not in {"secret", "match", "fingerprint"}},
            }
        )
    return items


def parse_grype(data: dict[str, Any], *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for match in data.get("matches") or []:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability") or {}
        art = match.get("artifact") or {}
        cve = vuln.get("id") or ""
        pkg = art.get("name") or ""
        ver = art.get("version") or ""
        title = f"{pkg}@{ver}: {cve}".strip(": ") if pkg else (vuln.get("description") or cve or "Grype finding")
        items.append(
            {
                "title": str(title)[:300],
                "cve": str(cve)[:40],
                "severity": _sev_norm(str(vuln.get("severity") or "Medium")),
                "asset_name": str(pkg or art.get("locations") or "sbom")[:200],
                "cvss": _cvss_from_grype(vuln),
                "engagement_id": engagement_id,
                "source": f"grype:{filename}",
                "raw": match,
            }
        )
    return items


def parse_checkov(data: dict[str, Any], *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    failed = data.get("failed_checks")
    if failed is None and isinstance(data.get("results"), dict):
        failed = data["results"].get("failed_checks")
    if not isinstance(failed, list):
        failed = []
    items: list[dict[str, Any]] = []
    for row in failed:
        if not isinstance(row, dict):
            continue
        cid = row.get("check_id") or row.get("id") or "checkov"
        name = row.get("check_name") or row.get("name") or cid
        path = row.get("file_path") or row.get("repo_file_path") or row.get("resource") or ""
        items.append(
            {
                "title": f"{cid}: {name}"[:300],
                "cve": str(cid)[:40],
                "severity": _sev_norm(str(row.get("severity") or "MEDIUM")),
                "asset_name": str(path)[:200],
                "cvss": None,
                "engagement_id": engagement_id,
                "source": f"checkov:{filename}",
                "raw": row,
            }
        )
    return items


def parse_bandit(data: dict[str, Any] | list, *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    rows = data.get("results") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        rows = []
    items: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        tid = row.get("test_id") or row.get("test_name") or "bandit"
        msg = row.get("issue_text") or row.get("issue_confidence") or tid
        cwe = row.get("cwe")
        cwe_id = ""
        if isinstance(cwe, dict):
            cwe_id = str(cwe.get("id") or "")
        elif cwe:
            cwe_id = str(cwe)
        items.append(
            {
                "title": f"{tid}: {msg}"[:300],
                "cve": cwe_id[:40],
                "severity": _sev_norm(str(row.get("issue_severity") or "MEDIUM")),
                "asset_name": str(row.get("filename") or "")[:200],
                "cvss": None,
                "engagement_id": engagement_id,
                "source": f"bandit:{filename}",
                "raw": row,
            }
        )
    return items


def parse_sonarqube(data: dict[str, Any], *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for issue in data.get("issues") or []:
        if not isinstance(issue, dict):
            continue
        # Prefer security-relevant types when present; still import others as findings
        itype = (issue.get("type") or "").upper()
        msg = issue.get("message") or issue.get("rule") or "SonarQube issue"
        rule = issue.get("rule") or ""
        comp = issue.get("component") or issue.get("project") or ""
        # Keep both the issue-type tag and the rule id — this used to overwrite
        # the "[VULNERABILITY]"/"[BUG]"/"[CODE_SMELL]" prefix entirely whenever
        # a rule id was present (which SonarQube always sets), silently losing
        # the type classification from every imported title.
        prefix = f"[{itype}] " if itype else ""
        title = f"{prefix}{rule}: {msg}" if rule else f"{prefix}{msg}"
        items.append(
            {
                "title": str(title)[:300],
                "cve": str(rule)[:40],
                "severity": _sev_norm(str(issue.get("severity") or "MAJOR")),
                "asset_name": str(comp)[:200],
                "cvss": None,
                "engagement_id": engagement_id,
                "source": f"sonarqube:{filename}",
                "raw": issue,
            }
        )
    return items


def parse_zap(data: dict[str, Any], *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    report_ver = str(data.get("@version") or "").strip()
    ver_u = report_ver.upper()
    # Honest source: builtin SecuraIQ report vs optional ZAP API / classic ZAP export.
    if "SECURAIQ" in ver_u:
        source_prefix = "securaiq_web"
        default_title = "Web finding"
    elif "ZAP-API" in ver_u or ver_u.startswith("ZAP"):
        source_prefix = "zap_api"
        default_title = "ZAP alert"
    elif report_ver and report_ver[0].isdigit():
        # Classic OWASP ZAP JSON export (e.g. "2.14.0").
        source_prefix = "zap_api"
        default_title = "ZAP alert"
    else:
        # Ambiguous / missing @version — do not claim OWASP ZAP.
        source_prefix = "securaiq_web"
        default_title = "Web finding"
    for site in data.get("site") or []:
        if not isinstance(site, dict):
            continue
        host = site.get("@name") or site.get("name") or site.get("@host") or "web-app"
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            name = alert.get("name") or alert.get("alert") or default_title
            plugin = alert.get("pluginid") or alert.get("pluginId") or ""
            engine = str(alert.get("engine") or source_prefix)
            row_prefix = "zap_api" if engine == "zap_api" else source_prefix
            items.append(
                {
                    "title": str(name)[:300],
                    "cve": str(plugin)[:40],
                    "severity": _sev_from_zap_risk(alert.get("riskcode"), str(alert.get("riskdesc") or "")),
                    "asset_name": str(host)[:200],
                    "cvss": None,
                    "engagement_id": engagement_id,
                    "source": f"{row_prefix}:{filename}",
                    "raw": {k: v for k, v in alert.items() if k != "instances"}
                    | {"instances_count": len(alert.get("instances") or []), "engine": engine},
                }
            )
    return items


def _sev_from_burp(sev: str) -> str:
    # Burp's own scale: High / Medium / Low / Information — "Information" isn't
    # in the shared _sev_norm map (only the JSON-scanner spelling "Informational"
    # is), so map it explicitly rather than let it fall through to "medium".
    s = (sev or "").strip().lower()
    if s == "information":
        return "info"
    return _sev_norm(sev, "info")


def is_burp_xml(text: str) -> bool:
    """Cheap, false-positive-resistant check before paying for a full XML parse."""
    head = text[:2000]
    return "<issues" in head and "<issue>" in text[:4000]


def is_greenbone_xml(text: str) -> bool:
    """Detect Greenbone/OpenVAS/GVM report XML (GMP get_reports style)."""
    head = (text or "")[:4000].lower()
    if "<issues" in head and "<issue>" in head:
        return False  # Burp
    markers = (
        "<nvt",
        "greenbone",
        "openvas",
        'extension="xml"',
        "<get_reports",
        "<report_format",
    )
    if any(m in head for m in markers):
        return True
    # Nested <report><results><result> is the classic OpenVAS export shape
    return "<results" in head and "<result>" in head and ("<threat>" in head or "<severity>" in head)


def parse_greenbone_xml(text: str, *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    """Greenbone Vulnerability Manager / OpenVAS report XML → finding rows.

    Accepts common export shapes: ``<report><results><result>…`` and GMP
    ``get_reports`` wrappers. Maps NVT name, host, port, threat/severity, CVE.
    """
    root = ET.fromstring(text)
    items: list[dict[str, Any]] = []
    # Prefer explicit result nodes; fall back to ReportItem-style if needed
    nodes = root.findall(".//result")
    if not nodes:
        nodes = root.findall(".//ReportItem")
    for node in nodes[:500]:
        nvt = node.find("nvt")
        title = ""
        cve = ""
        cvss = None
        oid = ""
        if nvt is not None:
            title = (nvt.findtext("name") or nvt.get("name") or "").strip()
            oid = (nvt.get("oid") or "").strip()
            cve_raw = (nvt.findtext("cve") or nvt.findtext("cves") or "").strip()
            if cve_raw and cve_raw.upper() not in {"NOCVE", "N/A", ""}:
                # First CVE token if comma/space separated
                cve = cve_raw.replace(",", " ").split()[0][:40]
            try:
                cvss = float(nvt.findtext("cvss_base") or nvt.findtext("cvss") or "")
            except (TypeError, ValueError):
                cvss = None
        if not title:
            title = (node.findtext("name") or node.findtext("nvt") or "Greenbone finding").strip()
        host = (node.findtext("host") or node.get("host") or "").strip()
        # Sometimes host is nested: <host><asset>...</asset>ip</host>
        if not host:
            host_el = node.find("host")
            if host_el is not None:
                host = "".join(host_el.itertext()).strip().split()[0] if host_el.text or list(host_el) else ""
        port = (node.findtext("port") or "").strip()
        asset = host or "target"
        if port and port not in {"general/tcp", "general/udp", ""}:
            asset = f"{asset}:{port.split('/')[0]}" if "/" in port else f"{asset}:{port}"
        threat = (node.findtext("threat") or node.findtext("severity") or "Medium").strip()
        try:
            if cvss is None:
                cvss = float(node.findtext("severity") or node.findtext("cvss") or "")
        except (TypeError, ValueError):
            pass
        desc = (node.findtext("description") or "")[:2000]
        items.append(
            {
                "title": str(title)[:300],
                "cve": (cve or "")[:40].upper(),
                "severity": _sev_norm(threat, "medium"),
                "asset_name": str(asset)[:200],
                "cvss": cvss,
                "engagement_id": engagement_id,
                "source": f"greenbone:{filename}",
                "raw": {
                    "oid": oid,
                    "host": host,
                    "port": port,
                    "threat": threat,
                    "description": desc,
                    "scanner": "greenbone",
                },
            }
        )
    return items


def parse_burp_xml(text: str, *, engagement_id: str | None, filename: str) -> list[dict[str, Any]]:
    """Burp Suite Scanner XML export (Professional or Community 'Save issues',
    also what Burp Suite Enterprise's report download produces). Each <issue>
    carries <name>, <host ip="...">https://target</host>, <path>, <severity>
    (High/Medium/Low/Information), <confidence> (Certain/Firm/Tentative), and
    CDATA background/remediation text we keep in `raw` for the finding detail
    view rather than parse into structured fields.
    """
    root = ET.fromstring(text)
    items: list[dict[str, Any]] = []
    for node in root.findall(".//issue")[:500]:
        name = (node.findtext("name") or "Burp finding").strip()
        host_el = node.find("host")
        host_url = (host_el.text or "").strip() if host_el is not None else ""
        host_ip = (host_el.get("ip") or "").strip() if host_el is not None else ""
        path = (node.findtext("path") or "").strip()
        asset = host_url or host_ip or "target"
        if path and path != "/":
            asset = f"{asset}{path}"
        confidence = (node.findtext("confidence") or "").strip()
        issue_type = (node.findtext("type") or "").strip()
        items.append(
            {
                "title": str(name)[:300],
                "cve": issue_type[:40],  # Burp's internal issue-type ID, not a CVE — kept for cross-reference
                "severity": _sev_from_burp(node.findtext("severity") or "Information"),
                "asset_name": str(asset)[:200],
                "cvss": None,  # Burp Scanner doesn't emit CVSS — severity is its own High/Medium/Low/Info scale
                "engagement_id": engagement_id,
                "source": f"burp:{filename}",
                "raw": {
                    "type": issue_type,
                    "host": host_url,
                    "host_ip": host_ip,
                    "path": path,
                    "confidence": confidence,
                    "severity": node.findtext("severity") or "",
                    "issueBackground": (node.findtext("issueBackground") or "")[:2000],
                    "remediationBackground": (node.findtext("remediationBackground") or "")[:2000],
                },
            }
        )
    return items


ADAPTERS: dict[str, Callable[..., list[dict[str, Any]]]] = {
    "trivy": parse_trivy,
    "semgrep": parse_semgrep,
    "gitleaks": parse_gitleaks,
    "grype": parse_grype,
    "checkov": parse_checkov,
    "bandit": parse_bandit,
    "sonarqube": parse_sonarqube,
    "zap": parse_zap,
}

# XML-format adapters live separately from ADAPTERS (which is JSON-only, keyed
# off try_parse_scanner_json) — app.enterprise.import_vulnerabilities checks
# is_burp_xml() directly before falling back to the generic _parse_xml_vulns
# for Nessus/other tools' XML exports.
XML_ADAPTERS: dict[str, Callable[..., list[dict[str, Any]]]] = {
    "burp": parse_burp_xml,
    "greenbone": parse_greenbone_xml,
    "openvas": parse_greenbone_xml,
}


def try_parse_scanner_json(
    text: str,
    *,
    filename: str,
    engagement_id: str | None,
) -> tuple[str | None, list[dict[str, Any]]]:
    """If JSON matches a scanner, return (adapter_name, normalized items)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None, []
    kind = detect_scanner_format(data, filename)
    if not kind:
        return None, []
    parser = ADAPTERS[kind]
    return kind, parser(data, engagement_id=engagement_id, filename=filename)


def list_import_adapters() -> list[str]:
    return sorted(set(ADAPTERS.keys()) | set(XML_ADAPTERS.keys()))
