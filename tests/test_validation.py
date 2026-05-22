"""Tests for validation.py — whitelist rules, the A1/A2/C1 fixes, null-bytes."""

import pytest

import validation as v
from validation import ValidationError


# ── username (lowercase-only; uppercase rejected) ─────────────────────────
def test_username_valid_lowercase_returned_unchanged():
    assert v.validate_username("myuser01") == "myuser01"


def test_username_uppercase_rejected():
    assert v.is_valid_username("ABCDEFGH") is False


@pytest.mark.parametrize("bad", ["ab", "1user", "a" * 11, "user with space"])
def test_username_rejects_invalid(bad):
    assert v.is_valid_username(bad) is False


# ── password rules ─────────────────────────────────────────────────────────
def test_password_requires_all_classes():
    assert v.is_valid_password("Abcdefg1!xyz", "u") is True


@pytest.mark.parametrize("bad", ["short1!A", "alllowercase1!", "NOLOWER1!", "NoDigits!!", "NoSpecial1A"])
def test_password_rejects_weak(bad):
    assert v.is_valid_password(bad, "u") is False


# ── employee-ID is EMP + 6 digits ─────────────────────────────────────────
@pytest.mark.parametrize("good", ["EMP123456", "EMP000001", "EMP999999"])
def test_employee_id_accepts_emp_format(good):
    assert v.validate_employee_id(good) == good


@pytest.mark.parametrize("bad", ["1234567", "EMP12345", "EMP1234567", "emp123456", "12a45"])
def test_employee_id_rejects_invalid(bad):
    assert v.is_valid_employee_id(bad) is False


# ── A1: validate_nonempty actually returns the value ──────────────────────
def test_nonempty_returns_value():
    assert v.validate_nonempty("hello") == "hello"


@pytest.mark.parametrize("bad", ["", "   "])
def test_nonempty_rejects_blank(bad):
    with pytest.raises(ValidationError):
        v.validate_nonempty(bad)


# ── domain formats ─────────────────────────────────────────────────────────
def test_zipcode_format():
    assert v.is_valid_zipcode("1234AB") is True
    assert v.is_valid_zipcode("1234ab") is False


def test_phone_prefix_added():
    assert v.validate_phone("12345678") == "+31-6-12345678"


def test_bsn_exactly_nine_digits():
    assert v.is_valid_bsn("123456789") is True
    assert v.is_valid_bsn("12345678") is False


def test_salary_batch_format():
    assert v.is_valid_salary_batch("2026-07") is True
    assert v.is_valid_salary_batch("2026-13") is False


# ── null-byte injection is rejected ───────────────────────────────────────
@pytest.mark.parametrize("payload", ["John\x00", "John%00", "John\\x00"])
def test_null_byte_rejected(payload):
    with pytest.raises(ValidationError):
        v.validate_name(payload, "First name")
