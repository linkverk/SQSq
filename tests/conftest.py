"""
Shared pytest fixtures for DeclaratieApp.

Everything is redirected to a per-test temp directory (DB, keys, logs,
backups) so the suite never touches src/data and tests stay isolated.
"""

import os
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

# Make the application modules importable.
SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

import database          # noqa: E402
import activity_log      # noqa: E402
import auth              # noqa: E402
import backup            # noqa: E402


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Point every module at a clean temp data/backup dir and seed the schema."""
    data = tmp_path / "data"
    data.mkdir()
    backups = tmp_path / "backups"
    backups.mkdir()

    # One shared Fernet key + AES key for the whole test.
    fernet_key = Fernet.generate_key()
    (data / "fernet_key.bin").write_bytes(fernet_key)
    aes_key = os.urandom(32)
    (data / "aes_key.bin").write_bytes(aes_key)

    # database.py — paths + live key/cipher objects.
    monkeypatch.setattr(database, "DATA_DIR", data)
    monkeypatch.setattr(database, "DB_PATH", data / "declaratieapp.db")
    monkeypatch.setattr(database, "AES_KEY_PATH", data / "aes_key.bin")
    monkeypatch.setattr(database, "FERNET_KEY_PATH", data / "fernet_key.bin")
    monkeypatch.setattr(database, "aes_key", aes_key)
    monkeypatch.setattr(database, "_fernet_key", fernet_key)
    monkeypatch.setattr(database, "fernet_cipher", Fernet(fernet_key))

    # activity_log.py — paths (it re-reads the Fernet key file lazily).
    monkeypatch.setattr(activity_log, "DATA_DIR", data)
    monkeypatch.setattr(activity_log, "LOG_FILE", data / "system.log")
    monkeypatch.setattr(activity_log, "FERNET_KEY_FILE", data / "fernet_key.bin")
    monkeypatch.setattr(activity_log, "LAST_CHECK_FILE", data / "last_log_check.txt")

    # backup.py — paths.
    monkeypatch.setattr(backup, "DATA_DIR", data)
    monkeypatch.setattr(backup, "BACKUP_DIR", backups)

    database.create_tables()
    database.init_super_admin()

    # Reset in-memory auth state between tests.
    auth._failed_attempts.clear()
    auth._session.update(
        logged_in=False, user_id=None, username=None, role=None, role_name=None,
        first_name=None, last_name=None, must_change_password=False, employee_id=None,
    )
    yield
    auth._failed_attempts.clear()


# ── login / seeding helpers ───────────────────────────────────────────────
SUPER_ADMIN = ("super_admin", "Admin_123?")
MANAGER_PW = "Manager_pass1!"
EMPLOYEE_PW = "Employee_pas1!"


@pytest.fixture
def as_super_admin():
    ok, _ = auth.login(*SUPER_ADMIN)
    assert ok
    return SUPER_ADMIN[0]


@pytest.fixture
def manager(as_super_admin):
    """Create a manager (as super admin) and return its username, logged out."""
    from users import create_manager
    ok, msg, _ = create_manager("mgruser01", "Meg", "Ployer", password=MANAGER_PW)
    assert ok, msg
    auth.logout()
    return "mgruser01"


@pytest.fixture
def employee(as_super_admin):
    """Create an employee profile + login account; return (username, employee_id)."""
    from employees import add_employee, _generate_employee_id
    from users import create_employee_account

    eid = _generate_employee_id()
    ok, msg = add_employee(
        "John", "Doe", "1990-01-01", "Male", "Mainstreet", "10",
        "1234AB", "Amsterdam", "john@example.com", "12345678",
        "Passport", "AB1234567", "123456789", employee_id=eid,
    )
    assert ok, msg
    ok, msg, _ = create_employee_account(
        "empuser01", "John", "Doe", employee_id=eid, password=EMPLOYEE_PW
    )
    assert ok, msg
    auth.logout()
    return "empuser01", eid
