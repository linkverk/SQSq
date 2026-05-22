"""Tests for backup.py — key exclusion, restore round-trip, one-use codes."""

import zipfile

import auth
import backup

SUPER = ("super_admin", "Admin_123?")
MANAGER_PW = "Manager_pass1!"


def test_backup_excludes_encryption_keys(as_super_admin):
    ok, msg, fname = backup.create_backup()
    assert ok, msg
    with zipfile.ZipFile(backup.BACKUP_DIR / fname) as zf:
        names = zf.namelist()
    assert "declaratieapp.db" in names
    assert "aes_key.bin" not in names
    assert "fernet_key.bin" not in names


def test_super_admin_restore_roundtrip(as_super_admin):
    ok, msg, fname = backup.create_backup()
    assert ok, msg
    ok, msg = backup.restore_backup(fname)
    assert ok, msg


def test_manager_needs_code_to_restore(manager):
    auth.login(*SUPER)
    ok, msg, fname = backup.create_backup()
    assert ok, msg
    auth.logout()

    auth.login("mgruser01", MANAGER_PW)
    ok, msg = backup.restore_backup(fname)        # no code
    assert not ok


def test_restore_code_is_one_use(manager):
    auth.login(*SUPER)
    ok, msg, fname = backup.create_backup()
    assert ok, msg
    ok, msg, code = backup.generate_restore_code(fname, "mgruser01")
    assert ok, msg
    auth.logout()

    auth.login("mgruser01", MANAGER_PW)
    ok, msg = backup.restore_backup(fname, code)   # first use OK
    assert ok, msg
    ok, msg = backup.restore_backup(fname, code)   # second use rejected
    assert not ok
