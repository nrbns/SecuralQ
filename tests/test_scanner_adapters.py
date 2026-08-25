"""Real assertions against the scanner import adapters — the parsers that
turn Trivy/Grype/Semgrep/Gitleaks/Checkov/Bandit/SonarQube/ZAP/Burp output
into vulnerability rows. Fixtures below mirror each tool's actual JSON/XML
shape (not simplified toy data) so a schema drift in a parser shows up here
instead of silently mis-scoring a real import.
"""

from __future__ import annotations

from app.scanner_adapters import (
    _sev_norm,
    detect_scanner_format,
    is_burp_xml,
    parse_bandit,
    parse_burp_xml,
    parse_checkov,
    parse_gitleaks,
    parse_grype,
    parse_semgrep,
    parse_sonarqube,
    parse_trivy,
    parse_zap,
    try_parse_scanner_json,
)


# --- severity normalization ---------------------------------------------


def test_sev_norm_maps_all_known_scales():
    assert _sev_norm("CRITICAL") == "critical"
    assert _sev_norm("BLOCKER") == "critical"
    assert _sev_norm("HIGH") == "high"
    assert _sev_norm("ERROR") == "high"
    assert _sev_norm("MEDIUM") == "medium"
    assert _sev_norm("WARNING") == "medium"
    assert _sev_norm("LOW") == "low"
    assert _sev_norm("MINOR") == "low"
    assert _sev_norm("INFO") == "info"
    assert _sev_norm("INFORMATIONAL") == "info"


def test_sev_norm_unknown_falls_back_to_default():
    assert _sev_norm("totally-made-up", "medium") == "medium"
    assert _sev_norm("", "low") == "low"


# --- Trivy -----------------------------------------------------------------


def test_parse_trivy_vulnerability_with_cvss():
    data = {
        "Results": [
            {
                "Target": "app/package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-12345",
                        "PkgName": "lodash",
                        "Title": "Prototype pollution",
                        "Severity": "HIGH",
                        "CVSS": {
                            "nvd": {"V3Score": 7.5, "V2Score": 5.0},
                            "redhat": {"V3Score": 7.3},
                        },
                    }
                ],
            }
        ]
    }
    items = parse_trivy(data, engagement_id="eng1", filename="trivy.json")
    assert len(items) == 1
    it = items[0]
    assert it["cve"] == "CVE-2023-12345"
    assert it["severity"] == "high"
    assert it["cvss"] == 7.5  # prefers nvd V3Score over other sources
    assert "lodash" in it["title"]
    assert it["asset_name"] == "app/package-lock.json"
    assert it["source"] == "trivy:trivy.json"
    assert it["engagement_id"] == "eng1"


def test_parse_trivy_cvss_falls_back_to_v2_when_no_v3():
    data = {
        "Results": [
            {
                "Target": "x",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "CVSS": {"nvd": {"V2Score": 4.3}}}
                ],
            }
        ]
    }
    items = parse_trivy(data, engagement_id=None, filename="t.json")
    assert items[0]["cvss"] == 4.3


def test_parse_trivy_secrets_and_misconfig_have_no_cvss():
    data = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [{"ID": "DS002", "Title": "Root user", "Severity": "MEDIUM"}],
                "Secrets": [{"RuleID": "aws-key", "Title": "AWS key", "Severity": "CRITICAL"}],
            }
        ]
    }
    items = parse_trivy(data, engagement_id=None, filename="t.json")
    kinds = {it["source"].split(":")[0].replace("trivy-", "") for it in items}
    assert "misconfig" in kinds or "secret" in kinds
    assert all(it["cvss"] is None for it in items)


# --- Grype -------------------------------------------------------------


def test_parse_grype_prefers_highest_cvss_version():
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-1",
                    "severity": "High",
                    "cvss": [
                        {"version": "2.0", "metrics": {"baseScore": 5.0}},
                        {"version": "3.1", "metrics": {"baseScore": 8.8}},
                    ],
                },
                "artifact": {"name": "openssl", "version": "1.1.1"},
            }
        ]
    }
    items = parse_grype(data, engagement_id=None, filename="grype.json")
    assert len(items) == 1
    assert items[0]["severity"] == "high"
    assert items[0]["cvss"] == 8.8  # 3.1 sorts after 2.0 lexicographically -> picked first
    assert items[0]["title"].startswith("openssl@1.1.1")


def test_parse_grype_missing_cvss_is_none():
    data = {"matches": [{"vulnerability": {"id": "CVE-X", "severity": "Low"}, "artifact": {"name": "pkg"}}]}
    items = parse_grype(data, engagement_id=None, filename="g.json")
    assert items[0]["cvss"] is None


# --- Semgrep / Bandit / Checkov / Gitleaks / SonarQube (no CVSS by design) --


def test_parse_semgrep_basic():
    data = {
        "results": [
            {
                "path": "src/app.py",
                "check_id": "python.flask.security.injection",
                "extra": {"severity": "ERROR", "message": "SQL injection risk"},
            }
        ]
    }
    items = parse_semgrep(data, engagement_id=None, filename="semgrep.json")
    assert items[0]["severity"] == "high"
    assert items[0]["asset_name"] == "src/app.py"
    assert items[0]["cvss"] is None


def test_parse_bandit_extracts_cwe_as_identifier():
    data = {
        "results": [
            {
                "test_id": "B608",
                "issue_text": "Possible SQL injection",
                "issue_severity": "MEDIUM",
                "filename": "db.py",
                "cwe": {"id": 89},
            }
        ]
    }
    items = parse_bandit(data, engagement_id=None, filename="bandit.json")
    assert items[0]["severity"] == "medium"
    assert items[0]["cve"] == "89"


def test_parse_checkov_failed_checks():
    data = {"results": {"failed_checks": [{"check_id": "CKV_AWS_1", "check_name": "S3 encrypted", "severity": "HIGH", "resource": "aws_s3_bucket.x"}]}}
    items = parse_checkov(data, engagement_id=None, filename="checkov.json")
    assert items[0]["severity"] == "high"
    assert "CKV_AWS_1" in items[0]["title"]


def test_parse_gitleaks_always_high_and_strips_secret_material():
    data = {"findings": [{"RuleID": "aws-access-key", "File": ".env", "Description": "AWS key", "Secret": "AKIA_SUPER_SECRET"}]}
    items = parse_gitleaks(data, engagement_id=None, filename="gitleaks.json")
    assert items[0]["severity"] == "high"
    assert "AKIA_SUPER_SECRET" not in str(items[0]["raw"])


def test_parse_sonarqube_vulnerability_type():
    data = {"issues": [{"type": "VULNERABILITY", "message": "Hardcoded credential", "rule": "python:S2068", "severity": "BLOCKER", "component": "app.py"}]}
    items = parse_sonarqube(data, engagement_id=None, filename="sonar.json")
    assert items[0]["severity"] == "critical"
    # Both the type classification and the rule id must survive into the
    # title — a prior version of this parser dropped the "[VULNERABILITY]"
    # prefix entirely whenever a rule id was present.
    assert "[VULNERABILITY]" in items[0]["title"]
    assert "python:S2068" in items[0]["title"]
    assert "Hardcoded credential" in items[0]["title"]


def test_parse_zap_risk_mapping():
    data = {
        "site": [
            {
                "@name": "http://target",
                "alerts": [{"name": "SQL Injection", "riskcode": "3", "riskdesc": "High (Medium)", "instances": [{}, {}]}],
            }
        ]
    }
    items = parse_zap(data, engagement_id=None, filename="zap.json")
    assert items[0]["severity"] == "high"
    assert items[0]["raw"]["instances_count"] == 2


# --- format auto-detection ------------------------------------------------


def test_detect_scanner_format_trivy_by_shape():
    assert detect_scanner_format({"Results": []}, "") == "trivy"


def test_detect_scanner_format_grype_by_shape():
    assert detect_scanner_format({"matches": []}, "") == "grype"


def test_detect_scanner_format_by_filename_hint():
    assert detect_scanner_format({}, "my-semgrep-scan.json") == "semgrep"


def test_try_parse_scanner_json_end_to_end():
    kind, items = try_parse_scanner_json(
        '{"Results":[{"Target":"x","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"LOW"}]}]}',
        filename="trivy-report.json",
        engagement_id=None,
    )
    assert kind == "trivy"
    assert len(items) == 1


def test_try_parse_scanner_json_invalid_json_returns_empty():
    kind, items = try_parse_scanner_json("not json at all", filename="x.json", engagement_id=None)
    assert kind is None
    assert items == []


# --- Burp Suite XML ----------------------------------------------------


BURP_XML = """<?xml version="1.0"?>
<issues burpVersion="2024.1" exportTime="Mon Jan 01 00:00:00 UTC 2026">
<issue>
<serialNumber>123</serialNumber>
<type>1049088</type>
<name>SQL injection</name>
<host ip="93.184.216.34">https://lab.example.com</host>
<path>/search</path>
<location>/search [q parameter]</location>
<severity>High</severity>
<confidence>Certain</confidence>
<issueBackground><![CDATA[The application appears vulnerable to SQL injection.]]></issueBackground>
<remediationBackground><![CDATA[Use parameterized queries.]]></remediationBackground>
</issue>
<issue>
<serialNumber>124</serialNumber>
<type>2097408</type>
<name>Cookie without HttpOnly flag</name>
<host ip="93.184.216.34">https://lab.example.com</host>
<path>/</path>
<severity>Information</severity>
<confidence>Firm</confidence>
</issue>
</issues>
"""


def test_is_burp_xml_detects_real_export():
    assert is_burp_xml(BURP_XML) is True


def test_is_burp_xml_rejects_other_xml():
    nessus_like = "<NessusClientData_v2><Report><ReportHost></ReportHost></Report></NessusClientData_v2>"
    assert is_burp_xml(nessus_like) is False


def test_parse_burp_xml_extracts_both_issues_with_correct_severity():
    items = parse_burp_xml(BURP_XML, engagement_id="eng9", filename="burp.xml")
    assert len(items) == 2

    sqli = items[0]
    assert sqli["title"] == "SQL injection"
    assert sqli["severity"] == "high"
    assert sqli["asset_name"] == "https://lab.example.com/search"
    assert sqli["cvss"] is None  # Burp Scanner has no CVSS concept
    assert sqli["source"] == "burp:burp.xml"
    assert sqli["raw"]["host_ip"] == "93.184.216.34"
    assert sqli["raw"]["confidence"] == "Certain"

    cookie = items[1]
    # This is the exact bug class the fix targets: Burp's "Information" must
    # map to "info", not fall through to "medium" or survive as "information".
    assert cookie["severity"] == "info"


def test_parse_burp_xml_empty_root_returns_empty_list():
    empty = '<?xml version="1.0"?><issues></issues>'
    assert parse_burp_xml(empty, engagement_id=None, filename="empty.xml") == []


GREENBONE_XML = """<?xml version="1.0"?>
<report id="r1">
  <results>
    <result id="1">
      <host>192.168.56.101</host>
      <port>443/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103674">
        <name>SSL/TLS: Report Vulnerable Cipher Suites</name>
        <cve>CVE-2016-2183</cve>
        <cvss_base>5.0</cvss_base>
      </nvt>
      <threat>Medium</threat>
      <severity>5.0</severity>
      <description>The remote service supports weak ciphers.</description>
    </result>
    <result id="2">
      <host>192.168.56.101</host>
      <port>22/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.105497">
        <name>OpenSSH Denial of Service Vulnerability</name>
        <cve>CVE-2016-6515</cve>
        <cvss_base>7.8</cvss_base>
      </nvt>
      <threat>High</threat>
      <severity>7.8</severity>
      <description>OpenSSH is prone to a DoS.</description>
    </result>
  </results>
</report>
"""


def test_is_greenbone_xml_detects_report():
    from app.scanner_adapters import is_greenbone_xml

    assert is_greenbone_xml(GREENBONE_XML) is True
    assert is_greenbone_xml(BURP_XML) is False


def test_parse_greenbone_xml_extracts_cve_and_severity():
    from app.scanner_adapters import parse_greenbone_xml

    items = parse_greenbone_xml(GREENBONE_XML, engagement_id="eng-g", filename="gvm.xml")
    assert len(items) == 2
    high = [i for i in items if i["severity"] == "high"][0]
    assert high["cve"] == "CVE-2016-6515"
    assert "192.168.56.101" in high["asset_name"]
    assert high["source"] == "greenbone:gvm.xml"
    assert high["cvss"] == 7.8
