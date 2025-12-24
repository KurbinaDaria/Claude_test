"""Unit tests for password_checker.checker module."""

import pytest
from password_checker.checker import (
    calculate_entropy,
    check_password_strength,
    COMMON_PASSWORDS
)


class TestEntropyCalculation:
    """Test entropy calculation function."""

    def test_empty_password(self):
        assert calculate_entropy("") == 0.0

    def test_single_character_repeated(self):
        entropy = calculate_entropy("aaaa")
        assert entropy == 0.0

    def test_all_different_characters(self):
        entropy = calculate_entropy("abcd")
        assert entropy > 0
        assert entropy == pytest.approx(8.0, rel=0.1)

    def test_mixed_repetition(self):
        entropy1 = calculate_entropy("aabbccdd")
        entropy2 = calculate_entropy("abcdabcd")
        assert entropy1 > 0
        assert entropy2 > 0

    def test_high_entropy_password(self):
        entropy = calculate_entropy("Xk9$mP2#vL8@qR5!")
        assert entropy > 50

    def test_low_entropy_password(self):
        entropy = calculate_entropy("aaaabbbb")
        assert entropy < 20


class TestBlacklistDetection:
    """Test blacklisted password detection."""

    def test_exact_blacklisted_password(self):
        result = check_password_strength("password")
        assert result["is_blacklisted"] is True
        assert result["score"] == 0
        assert result["strength"] == "Very Weak"

    def test_blacklisted_password_case_insensitive(self):
        result = check_password_strength("PASSWORD")
        assert result["is_blacklisted"] is True
        assert result["score"] == 0

    def test_multiple_blacklisted_passwords(self):
        blacklisted = ["123456", "qwerty", "password123", "admin"]
        for password in blacklisted:
            result = check_password_strength(password)
            assert result["is_blacklisted"] is True

    def test_non_blacklisted_password(self):
        result = check_password_strength("MySecureP@ss123")
        assert result["is_blacklisted"] is False

    def test_blacklisted_password_has_warning(self):
        result = check_password_strength("letmein")
        assert result["is_blacklisted"] is True
        assert "leaked password" in result["feedback"][0].lower()


class TestPasswordStrength:
    """Test password strength scoring."""

    def test_very_weak_password(self):
        result = check_password_strength("abc")
        assert result["strength"] == "Very Weak"
        assert result["score"] < 40

    def test_weak_password(self):
        result = check_password_strength("abcdefgh")
        assert result["score"] < 60

    def test_moderate_password(self):
        result = check_password_strength("Abcdef123")
        assert 40 <= result["score"] < 80

    def test_strong_password(self):
        result = check_password_strength("MyP@ssw0rd123!")
        assert result["score"] >= 60

    def test_very_strong_password(self):
        result = check_password_strength("Xk9$mP2#vL8@qR5!")
        assert result["score"] >= 80
        assert result["strength"] == "Strong"


class TestPasswordCharacteristics:
    """Test password characteristic detection."""

    def test_lowercase_only(self):
        result = check_password_strength("abcdefgh")
        assert "uppercase" in str(result["feedback"]).lower()
        assert "numbers" in str(result["feedback"]).lower()
        assert "special" in str(result["feedback"]).lower()

    def test_uppercase_only(self):
        result = check_password_strength("ABCDEFGH")
        assert "lowercase" in str(result["feedback"]).lower()

    def test_numbers_only(self):
        result = check_password_strength("12345678")
        assert "lowercase" in str(result["feedback"]).lower()
        assert "uppercase" in str(result["feedback"]).lower()

    def test_all_character_types(self):
        result = check_password_strength("Abc123!@#")
        feedback_str = str(result["feedback"]).lower()
        assert "lowercase" not in feedback_str or result["score"] > 60

    def test_length_feedback(self):
        result = check_password_strength("Ab1!")
        assert any("8 characters" in fb for fb in result["feedback"])

    def test_long_password_bonus(self):
        short_result = check_password_strength("Abc123!@")
        long_result = check_password_strength("Abc123!@#$%^")
        assert long_result["score"] >= short_result["score"]


class TestEntropyFeedback:
    """Test entropy-based feedback."""

    def test_low_entropy_feedback(self):
        result = check_password_strength("aabbccdd")
        assert any("low entropy" in fb.lower() for fb in result["feedback"])

    def test_high_entropy_feedback(self):
        result = check_password_strength("Xk9$mP2#vL8@qR5!")
        assert any("good entropy" in fb.lower() for fb in result["feedback"])

    def test_entropy_included_in_result(self):
        result = check_password_strength("test123")
        assert "entropy" in result
        assert isinstance(result["entropy"], (int, float))
        assert result["entropy"] >= 0


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_empty_password(self):
        result = check_password_strength("")
        assert result["score"] == 0
        assert result["strength"] == "Very Weak"

    def test_whitespace_password(self):
        result = check_password_strength("    ")
        assert result["score"] < 40

    def test_unicode_characters(self):
        result = check_password_strength("Pässw0rd!")
        assert "entropy" in result
        assert result["score"] > 0

    def test_very_long_password(self):
        result = check_password_strength("A1b@" * 20)
        assert result["score"] >= 60

    def test_result_structure(self):
        result = check_password_strength("Test123!")
        assert "score" in result
        assert "strength" in result
        assert "feedback" in result
        assert "entropy" in result
        assert "is_blacklisted" in result

    def test_score_never_exceeds_100(self):
        result = check_password_strength("VeryL0ng&C0mpl3x!P@ssw0rd" * 10)
        assert result["score"] <= 100
