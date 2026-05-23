# Tests for cvss_scorer.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import cvss_scorer

def test_critical_severity():
    assert cvss_scorer.get_severity(9.5) == "CRITICAL"

def test_high_severity():
    assert cvss_scorer.get_severity(8.0) == "HIGH"

def test_medium_severity():
    assert cvss_scorer.get_severity(5.5) == "MEDIUM"

def test_low_severity():
    assert cvss_scorer.get_severity(2.0) == "LOW"

def test_none_severity():
    assert cvss_scorer.get_severity(0.0) == "NONE"

def test_score_boundary_critical():
    assert cvss_scorer.get_severity(9.0) == "CRITICAL"

def test_score_boundary_high():
    assert cvss_scorer.get_severity(7.0) == "HIGH"
