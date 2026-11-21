
from app.dld_engine import evaluate_access


def test_normal_authorized_access():
    result = evaluate_access(
        True, True, False, False, False, False
    )
    assert result["ALLOW"] is True
    assert result["BLOCK"] is False


def test_unauthenticated_access():
    result = evaluate_access(
        False, True, False, False, False, False
    )
    assert result["ALLOW"] is False
    assert result["BLOCK"] is True
    assert result["ALERT"] is True


def test_permission_denied():
    result = evaluate_access(
        True, False, False, False, False, False
    )
    assert result["ALLOW"] is False
    assert result["ALERT"] is True


def test_sensitive_file_without_extra_verification():
    result = evaluate_access(
        True, True, True, False, False, False
    )
    assert result["ALLOW"] is False


def test_sensitive_file_with_extra_verification():
    result = evaluate_access(
        True, True, True, True, False, False
    )
    assert result["ALLOW"] is True


def test_high_risk_access():
    result = evaluate_access(
        True, True, False, False, True, False
    )
    assert result["ALLOW"] is False
    assert result["ALERT"] is True


def test_suspicious_export():
    result = evaluate_access(
        True, True, False, False, False, True
    )
    assert result["ALLOW"] is False
    assert result["ALERT"] is True
