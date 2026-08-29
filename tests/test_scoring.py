from __future__ import annotations

import pytest

from redready.engine.result import Finding, severity_for_score
from redready.intel.scorer import risk_score, score_finding
from redready.intel.sources.version import (
    compare_versions,
    decode_bound,
    encode_bound,
    parse_version,
    version_in_range,
)


def test_full_formula_matches_spec() -> None:
    # (9.8/10 * 0.4) + (0.5 * 0.35) + (0.2 * 0.25)
    assert risk_score(9.8, 0.5, 0.2) == pytest.approx(0.617, abs=1e-3)


def test_missing_components_redistribute_weights() -> None:
    assert risk_score(10.0, None, None) == pytest.approx(1.0)
    assert risk_score(None, None, None) is None


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (0.95, "CRITICAL"),
        (0.8, "CRITICAL"),
        (0.65, "HIGH"),
        (0.45, "MEDIUM"),
        (0.25, "LOW"),
        (0.0, "INFO"),
    ],
)
def test_severity_thresholds(score: float, severity: str) -> None:
    assert severity_for_score(score) == severity


def test_score_finding_uses_severity_when_no_intel() -> None:
    finding = score_finding(
        Finding(module="dns", title="t", description="d", severity="HIGH", remediation="r")
    )
    assert finding.risk_score == pytest.approx(0.7)
    assert finding.severity == "HIGH"


def test_score_finding_never_downgrades_module_severity() -> None:
    finding = score_finding(
        Finding(
            module="tls",
            title="t",
            description="d",
            severity="CRITICAL",
            remediation="r",
            cvss_score=2.0,
        )
    )
    assert finding.severity == "CRITICAL"


def test_version_comparison() -> None:
    assert compare_versions("1.2.3", "1.10.0") < 0
    assert compare_versions("2.0", "2.0.0") == 0
    assert compare_versions("8.2p1", "8.2") > 0
    assert parse_version("1.2")[0] == (1, "")


def test_version_ranges() -> None:
    start = encode_bound("7.0", inclusive=True)
    end = encode_bound("8.0", inclusive=False)
    assert version_in_range("7.4", exact="7.4")
    assert not version_in_range("7.5", exact="7.4")
    assert version_in_range("7.0", start_including=start, end_excluding=end)
    assert not version_in_range("8.0", start_including=start, end_excluding=end)
    assert not version_in_range("6.9", start_including=start, end_excluding=end)


def test_bound_encoding_roundtrip() -> None:
    assert decode_bound(encode_bound("1.2", inclusive=False)) == (False, "1.2")
    assert decode_bound("1.2") == (True, "1.2")
