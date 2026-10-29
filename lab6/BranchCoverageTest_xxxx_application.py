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


# ================= Branch coverage additions =================

# check_password: `len < 8` True boundary (7 chars, just under the limit)
def test_length_7_is_too_short():
    assert check_password("Abcde1!") == ["too short"]

# check_password: `len < 8` False and `len > 64` False at lower boundary (exactly 8)
def test_length_8_is_accepted():
    assert check_password("Abcdef1!") == []

# check_password: `len > 64` False at upper boundary (exactly 64)
def test_length_64_is_accepted():
    pw = "Aa1!" + "a" * 60
    assert len(pw) == 64
    assert check_password(pw) == []

# check_password: `len > 64` True at boundary (exactly 65)
def test_length_65_is_too_long():
    pw = "Aa1!" + "a" * 61
    assert len(pw) == 65
    assert check_password(pw) == ["too long"]

# check_password: for-loop runs zero times (empty string) and every "no X" check is True
def test_empty_password_loop_zero_iterations():
    assert check_password("") == [
        "too short", "no uppercase", "no lowercase", "no digit", "no special"
    ]

# check_password: for-loop runs exactly once (single character) and exits normally
def test_single_character_loop_one_iteration():
    assert check_password("A") == [
        "too short", "no lowercase", "no digit", "no special"
    ]

# check_password: `else` (special) branch via non-alphanumeric characters, incl. space
def test_space_and_underscore_count_as_special():
    assert check_password("Abcdef1 _") == []

# check_password: `isdigit` True and `else` False for a digit-only run
def test_digits_only_password():
    assert check_password("12345678") == ["no uppercase", "no lowercase", "no special"]

# check_password: `common` True with mixed case, `common` False for non-listed word
def test_common_check_true_and_false():
    assert "common" in check_password("PassWord")
    assert "common" not in check_password("Passw0rd!")

# check_password: `common` True alongside `too short` (both ifs fire independently)
def test_short_and_common():
    assert check_password("qwerty")[:2] == ["too short", "common"]

# strength: `not issues` True, `len >= 14` False at boundary (13 chars -> good)
def test_strength_length_13_is_good():
    pw = "Abcdefghij1!A"
    assert len(pw) == 13
    assert strength(pw) == "good"

# strength: `not issues` True, `len >= 14` True at boundary (14 chars -> strong)
def test_strength_length_14_is_strong():
    pw = "Abcdefghij1!AB"
    assert len(pw) == 14
    assert strength(pw) == "strong"

# strength: `len(issues) <= 2` True at boundary (exactly 2 issues -> weak)
def test_strength_exactly_two_issues_is_weak():
    assert check_password("abcdefgh!") == ["no uppercase", "no digit"]
    assert strength("abcdefgh!") == "weak"

# strength: `len(issues) <= 2` False at boundary (exactly 3 issues -> very weak)
def test_strength_exactly_three_issues_is_very_weak():
    assert len(check_password("abcdefgh")) == 3
    assert strength("abcdefgh") == "very weak"

# strength: empty input (5 issues) -> very weak
def test_strength_empty_string():
    assert strength("") == "very weak"

# suggest_fix: `first == "too short"` True via real check_password output
def test_suggest_fix_from_real_short_password():
    assert suggest_fix(check_password("Ab1!")) == "add more characters"

# suggest_fix: `first == "common"` False and `startswith("no ")` True for each class
def test_suggest_fix_each_missing_class():
    assert suggest_fix(["no uppercase"]) == "add uppercase"
    assert suggest_fix(["no lowercase"]) == "add lowercase"
    assert suggest_fix(["no special"]) == "add special"

# suggest_fix: `startswith("no ")` False -> fallthrough "shorten it" via real output
def test_suggest_fix_from_real_long_password():
    assert suggest_fix(check_password("Aa1!" + "a" * 61)) == "shorten it"

# suggest_fix: `not issues` True via real output of a valid password
def test_suggest_fix_from_real_valid_password():
    assert suggest_fix(check_password("Abcdef1!")) == "none needed"
