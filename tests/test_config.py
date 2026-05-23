# Tests for config.py — checks all paths exist after import
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def test_output_dir_created():
    assert os.path.exists(config.OUTPUT_DIR)

def test_reports_dir_created():
    assert os.path.exists(config.REPORTS_DIR)

def test_graphs_dir_created():
    assert os.path.exists(config.GRAPHS_DIR)

def test_severity_levels_exist():
    assert "CRITICAL" in config.SEVERITY
    assert "HIGH" in config.SEVERITY
    assert "MEDIUM" in config.SEVERITY
    assert "LOW" in config.SEVERITY

def test_port_scan_settings():
    assert config.TOP_PORTS > 0
    assert config.SUBDOMAIN_THREADS > 0
    assert config.REQUEST_TIMEOUT > 0
