"""Unit tests for app.services.risk.compute_risk_score / explain_risk_score —
the deterministic scoring primitive every risk feature in the product reuses
(priority list, organizational score, simulator, campaign risk deltas).

Covers the two hardening additions: compensating_controls (a real mitigation
signal that should LOWER the score) and business_criticality (a distinct
signal from asset_criticality that falls back to it when unset).
"""

from __future__ import annotations

from app.services.risk import compute_risk_score, explain_risk_score


def _base_kwargs():
    return dict(cvss=8.0, exploitability=0.8, exposure=0.8, asset_criticality="high", threat_intel=0.5, confidence=0.7)


def test_score_is_deterministic_for_same_inputs():
    a = compute_risk_score(**_base_kwargs())
    b = compute_risk_score(**_base_kwargs())
    assert a["score"] == b["score"]


def test_weights_sum_to_one():
    result = compute_risk_score(**_base_kwargs())
    assert abs(sum(result["weights"].values()) - 1.0) < 1e-9


def test_score_stays_in_0_100_range_across_extremes():
    lo = compute_risk_score(cvss=0.0, exploitability=0.0, exposure=0.0, asset_criticality="info", threat_intel=0.0, confidence=0.0, compensating_controls=1.0)
    hi = compute_risk_score(cvss=10.0, exploitability=1.0, exposure=1.0, asset_criticality="critical", threat_intel=1.0, confidence=1.0, compensating_controls=0.0, business_criticality="critical")
    assert 0.0 <= lo["score"] <= 100.0
    assert 0.0 <= hi["score"] <= 100.0
    assert lo["score"] < hi["score"]


def test_compensating_controls_lowers_score():
    """A real mitigation signal (e.g. active agent monitoring) must reduce
    the score relative to an identical finding with no known controls."""
    unmitigated = compute_risk_score(**_base_kwargs(), compensating_controls=0.0)
    mitigated = compute_risk_score(**_base_kwargs(), compensating_controls=0.8)
    assert mitigated["score"] < unmitigated["score"]
    assert mitigated["factors"]["compensating_controls"] == 0.8


def test_compensating_controls_defaults_to_zero_when_unset():
    """Unset must mean 'assume no mitigation' (conservative), not 'assume
    full mitigation' — never invent protection that wasn't confirmed."""
    explicit_zero = compute_risk_score(**_base_kwargs(), compensating_controls=0.0)
    unset = compute_risk_score(**_base_kwargs())
    assert explicit_zero["score"] == unset["score"]
    assert unset["factors"]["compensating_controls"] == 0.0


def test_business_criticality_falls_back_to_asset_criticality_when_unset():
    result = compute_risk_score(**_base_kwargs())
    assert result["factors"]["business_criticality"] == result["factors"]["asset_criticality"]


def test_business_criticality_overrides_when_explicit_and_diverges():
    """The canonical case: a low-criticality box (asset_criticality=low)
    holding business-critical data (business_criticality=critical) must
    score higher than an identical box with no elevated business function."""
    low_only = compute_risk_score(cvss=6.0, exploitability=0.5, exposure=0.5, asset_criticality="low", threat_intel=0.3, confidence=0.7)
    with_business_crit = compute_risk_score(cvss=6.0, exploitability=0.5, exposure=0.5, asset_criticality="low", threat_intel=0.3, confidence=0.7, business_criticality="critical")
    assert with_business_crit["score"] > low_only["score"]
    assert with_business_crit["factors"]["business_criticality"] == 1.0
    assert with_business_crit["factors"]["asset_criticality"] == low_only["factors"]["asset_criticality"]


def test_explain_includes_new_factors():
    result = compute_risk_score(**_base_kwargs(), compensating_controls=0.5, business_criticality="critical")
    explanation = explain_risk_score(result)
    assert "compensating_controls" in explanation
    assert "business_criticality" in explanation


def test_compensating_from_host_controls_pass_above_monitoring_only():
    from app.services.risk_priority import _compensating_from_host_controls

    monitor_only, _, _, _ = _compensating_from_host_controls(is_monitored=True, host_statuses={})
    with_pass, reasons, passes, fails = _compensating_from_host_controls(
        is_monitored=True,
        host_statuses={
            "host_firewall": "pass",
            "host_disk_encryption": "pass",
            "host_defender": "pass",
            "host_ssh_root": "pass",
        },
    )
    assert with_pass > monitor_only
    assert with_pass <= 0.85
    assert set(passes) == {
        "host_firewall",
        "host_disk_encryption",
        "host_defender",
        "host_ssh_root",
    }
    assert fails == []
    assert any("host_firewall PASS" in r for r in reasons)


def test_compensating_from_host_controls_fail_below_monitoring_only():
    from app.services.risk_priority import _compensating_from_host_controls

    monitor_only, _, _, _ = _compensating_from_host_controls(is_monitored=True, host_statuses={})
    with_fail, reasons, passes, fails = _compensating_from_host_controls(
        is_monitored=True,
        host_statuses={"host_firewall": "fail", "host_disk_encryption": "fail"},
    )
    assert with_fail < monitor_only
    assert with_fail >= 0.0
    assert passes == []
    assert "host_firewall" in fails
    assert any("host_firewall FAIL" in r for r in reasons)


def test_compensating_from_host_controls_unknown_ignored():
    """UNKNOWN / absent host results must not invent PASS compensation."""
    from app.services.risk_priority import _compensating_from_host_controls

    a, _, _, _ = _compensating_from_host_controls(is_monitored=True, host_statuses={})
    b, reasons, passes, fails = _compensating_from_host_controls(
        is_monitored=True,
        host_statuses={},  # decisive map omits unknown
    )
    assert a == b == 0.5
    assert passes == [] and fails == []
    assert reasons == ["Partially offset by active agent monitoring"]


def test_threat_intel_with_active_threats_kev_dominates():
    from app.services.risk_priority import _threat_intel_with_active_threats

    v, reasons = _threat_intel_with_active_threats(
        is_kev=True,
        active={"count": 3, "max_severity": "critical", "categories": ["file_integrity"]},
    )
    assert v == 0.9
    assert any("KEV" in r for r in reasons)


def test_threat_intel_with_active_threats_bumps_non_kev():
    from app.services.risk_priority import _threat_intel_with_active_threats

    base, _ = _threat_intel_with_active_threats(is_kev=False, active=None)
    bumped, reasons = _threat_intel_with_active_threats(
        is_kev=False,
        active={"count": 2, "max_severity": "high", "categories": ["security_log"]},
    )
    assert bumped > base
    assert any("Active agent threat" in r for r in reasons)


def test_kev_style_high_threat_intel_still_dominant_with_full_mitigation():
    """Even with strong compensating controls, an actively-exploited
    critical CVE on a critical asset should not fall to a low/info band —
    mitigation reduces risk, it doesn't erase it."""
    result = compute_risk_score(
        cvss=9.8, exploitability=0.95, exposure=0.9, asset_criticality="critical",
        threat_intel=0.9, confidence=0.9, compensating_controls=0.5,
    )
    assert result["band"] in ("high", "critical")
