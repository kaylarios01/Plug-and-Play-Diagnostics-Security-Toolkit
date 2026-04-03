import pytest
from network_scanning.scanner import NetworkScanner

def test_scanner_initialization():
    scanner = NetworkScanner()
    assert scanner is not None
