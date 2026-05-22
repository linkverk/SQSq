"""Tests for auth.py — login, lockout, case-sensitive usernames, password change."""

import auth


def test_super_admin_login_ok():
    ok, msg = auth.login("super_admin", "Admin_123?")
    assert ok
    assert auth.is_logged_in()


def test_super_admin_login_uppercase_rejected():
    # Usernames are case-sensitive (lowercase-only); the uppercase variant is rejected.
    ok, _ = auth.login("SUPER_ADMIN", "Admin_123?")
    assert not ok


def test_login_wrong_password_fails():
    ok, msg = auth.login("super_admin", "Wrong_pass123!")
    assert not ok
    assert not auth.is_logged_in()


def test_lockout_after_three_attempts():
    msgs = [auth.login("lockme01", "Wrongpass123!")[1] for _ in range(3)]
    assert "locked" in msgs[-1].lower()


def test_check_permission_requires_login():
    assert auth.check_permission("create_backup") is False


def test_employee_login_and_permissions(employee):
    username, _ = employee
    ok, _ = auth.login(username, "Employee_pas1!")
    assert ok
    assert auth.check_permission("add_claim") is True
    assert auth.check_permission("add_manager") is False


def test_password_change_rejects_weak(as_super_admin):
    ok, msg = auth.update_password("Admin_123?", "weak")
    assert not ok
