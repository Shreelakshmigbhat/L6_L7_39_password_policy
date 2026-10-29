import pytest
from password_policy import check_password, strength, suggest_fix

#Example test cases:
def test_valid_password_has_no_issues():
    assert check_password("Abcdef1!") == []

def test_valid_password_is_good():
    assert strength("Abcdef1!") == "good"


# ---- check_password ----
def test_too_short():
    assert check_password("Ab1!") == ["too short"]

def test_too_long():
    assert check_password("Aa1!" + "a" * 61) == ["too long"]

def test_common_password():
    assert check_password("password") == [
        "common", "no uppercase", "no digit", "no special"
    ]

def test_common_password_is_case_insensitive():
    assert "common" in check_password("QWERTY")

def test_no_uppercase():
    assert check_password("abcdef1!") == ["no uppercase"]

def test_no_lowercase():
    assert check_password("ABCDEF1!") == ["no lowercase"]

def test_no_digit():
    assert check_password("Abcdefg!") == ["no digit"]

def test_no_special():
    assert check_password("Abcdefg1") == ["no special"]


# ---- strength ----
def test_strong_password():
    assert strength("Abcdef1!Abcdef1!") == "strong"

def test_weak_one_issue():
    assert strength("abcdefg1!") == "weak"

def test_weak_two_issues():
    assert strength("abcdefgh!") == "weak"

def test_very_weak():
    assert strength("password") == "very weak"


# ---- suggest_fix ----
def test_suggest_fix_no_issues():
    assert suggest_fix([]) == "none needed"

def test_suggest_fix_too_short():
    assert suggest_fix(["too short"]) == "add more characters"

def test_suggest_fix_common():
    assert suggest_fix(["common", "no digit"]) == "avoid common passwords"

def test_suggest_fix_missing_class():
    assert suggest_fix(["no digit"]) == "add digit"

def test_suggest_fix_too_long():
    assert suggest_fix(["too long"]) == "shorten it"
