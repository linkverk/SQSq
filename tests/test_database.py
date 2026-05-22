"""Tests for database.py — encryption round-trips and password hashing."""

import database as db


def test_username_aes_roundtrip():
    enc = db.encrypt_username("alice01")
    assert enc != "alice01"
    assert db.decrypt_username(enc) == "alice01"


def test_username_aes_is_deterministic():
    # ECB is deterministic by design (kept + documented as a trade-off).
    assert db.encrypt_username("alice01") == db.encrypt_username("alice01")


def test_field_fernet_roundtrip():
    enc = db.encrypt_field("123456789")
    assert enc != "123456789"
    assert db.decrypt_field(enc) == "123456789"


def test_field_fernet_is_non_deterministic():
    assert db.encrypt_field("secret") != db.encrypt_field("secret")


def test_empty_values_passthrough():
    assert db.encrypt_username("") == ""
    assert db.encrypt_field("") == ""


def test_password_hash_verify():
    h = db.hash_password("Abcdefg1!xyz")
    assert "$" in h
    assert db.verify_password("Abcdefg1!xyz", "u", h) is True
    assert db.verify_password("wrongpass", "u", h) is False


def test_password_hash_is_salted():
    assert db.hash_password("Abcdefg1!xyz") != db.hash_password("Abcdefg1!xyz")
