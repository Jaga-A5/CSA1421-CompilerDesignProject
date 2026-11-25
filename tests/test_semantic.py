"""
Unit tests for Module 3: Semantic Analysis and Vulnerability Detection
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.semantic.analyzer import SemanticAnalyzer, VulnerabilityType, Severity, analyze_vulnerabilities


def test_sql_injection_detection():
    """Test SQL injection detection"""
    analyzer = SemanticAnalyzer()
    code = 'query = "SELECT * FROM users WHERE name = \'" + user_input + "\'"'
    vulnerabilities = analyzer.analyze(code)
    
    sql_injection = [v for v in vulnerabilities if v.type == VulnerabilityType.SQL_INJECTION]
    assert len(sql_injection) > 0
    print("test_sql_injection_detection: PASSED")


def test_hardcoded_credentials_detection():
    """Test hardcoded credentials detection"""
    analyzer = SemanticAnalyzer()
    code = 'password = "admin123"'
    vulnerabilities = analyzer.analyze(code)
    
    credentials = [v for v in vulnerabilities if v.type == VulnerabilityType.HARDCODED_CREDENTIALS]
    assert len(credentials) > 0
    print("test_hardcoded_credentials_detection: PASSED")


def test_eval_detection():
    """Test eval() detection"""
    analyzer = SemanticAnalyzer()
    code = 'result = eval(user_input)'
    vulnerabilities = analyzer.analyze(code)
    
    xss = [v for v in vulnerabilities if v.type == VulnerabilityType.XSS]
    assert len(xss) > 0
    print("test_eval_detection: PASSED")


def test_weak_crypto_detection():
    """Test weak cryptography detection"""
    analyzer = SemanticAnalyzer()
    code = 'hash = md5(data)'
    vulnerabilities = analyzer.analyze(code)
    
    weak_crypto = [v for v in vulnerabilities if v.type == VulnerabilityType.WEAK_CRYPTO]
    assert len(weak_crypto) > 0
    print("test_weak_crypto_detection: PASSED")


def test_security_score():
    """Test security score calculation"""
    code = 'password = "admin123"\nquery = "SELECT * FROM users WHERE name = \'" + input + "\'"'
    vulnerabilities, summary, score = analyze_vulnerabilities(code)
    
    assert score < 100  # Should have vulnerabilities
    assert summary['total'] > 0
    print("test_security_score: PASSED")


def test_vulnerability_summary():
    """Test vulnerability summary generation"""
    code = 'password = "admin123"\nhash = md5(data)'
    vulnerabilities, summary, score = analyze_vulnerabilities(code)
    
    assert 'by_severity' in summary
    assert 'by_type' in summary
    assert summary['total'] > 0
    print("test_vulnerability_summary: PASSED")


if __name__ == '__main__':
    test_sql_injection_detection()
    test_hardcoded_credentials_detection()
    test_eval_detection()
    test_weak_crypto_detection()
    test_security_score()
    test_vulnerability_summary()
    print("\nAll semantic analysis tests passed!")
