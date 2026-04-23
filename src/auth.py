"""
auth.py – Authentication, session management and role-based access control.

Roles: super_admin, manager, employee.
Session is in-memory only (resets on restart).
"""

from database import (
    get_connection, encrypt_username, decrypt_username,
    hash_password, verify_password,
)
from validation import is_valid_username, is_valid_password, validate_password, validate_username, ValidationError
from activity_log import log_activity
from datetime import datetime, timedelta

# ── session state ────────────────────────────────────────────────────────
_session = {
    "logged_in": False, "user_id": None, "username": None,
    "role": None, "role_name": None, "first_name": None,
    "last_name": None, "employee_id": None, "must_change_password": False,
}

ROLE_NAMES = {
    "super_admin": "Super Administrator",
    "manager": "Manager",
    "employee": "Employee",
}

# ── permission matrix ────────────────────────────────────────────────────
PERMISSIONS = {
    "super_admin": {
        "modify_claim", "approve_claim", "assign_salary_batch", "view_claims",
        "view_employees", "add_employee", "update_employee", "delete_employee",
        "reset_employee_password",
        "add_manager", "update_manager", "delete_manager", "reset_manager_password",
        "view_logs", "create_backup", "restore_backup",
        "generate_restore_code", "revoke_restore_code",
        "update_own_password",
    },
    "manager": {
        "modify_claim", "approve_claim", "assign_salary_batch", "view_claims",
        "view_employees", "add_employee", "update_employee", "delete_employee",
        "reset_employee_password",
        "view_logs", "create_backup", "restore_backup",
        "update_own_password", "update_own_account", "delete_own_account",
    },
    "employee": {
        "view_claims", "add_claim", "update_own_claim",
        "update_own_password",
    },
}


# ── brute-force protection ───────────────────────────────────────────────
_failed_attempts = {}  # {username_lower: {"count": int, "locked_until": datetime|None}}
_LOCKOUT_THRESHOLD = 3
_LOCKOUT_DURATION = timedelta(minutes=5)


# ── public API ───────────────────────────────────────────────────────────
def get_current_user():
    return _session.copy() if _session["logged_in"] else None


def is_logged_in():
    return _session["logged_in"]


def get_role_name(role):
    return ROLE_NAMES.get(role, role)


def check_permission(perm):
    if _session["logged_in"]:
        return perm in PERMISSIONS.get(_session["role"], set())
    return False


def require_permission(perm):
    if _session["logged_in"] and check_permission(perm):
        return True, None
    if not _session["logged_in"]:
        return False, "You must be logged in."
    if not check_permission(perm):
        return False, f"Access denied. Role '{_session['role']}' lacks permission: {perm}"
    return False, "Access denied."


# ── login / logout ───────────────────────────────────────────────────────
def login(username, password):
    # ── whitelist: validate input format first ───────────────────────
    if is_valid_username(username, allow_super_admin=True) and is_valid_password(password, username):

        # ── check if account is temporarily locked ───────────────────
        if username in _failed_attempts:
            info = _failed_attempts[username]
            if info["locked_until"] and datetime.now() < info["locked_until"]:
                remaining = (info["locked_until"] - datetime.now()).seconds // 60 + 1
                log_activity("unknown", "Login blocked",
                             f"Account '{username}' is locked ({remaining} min remaining)",
                             suspicious=True)
                return False, f"Account temporarily locked. Try again in {remaining} minute(s)."

        # ── lookup user ──────────────────────────────────────────────
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "SELECT id, username, password_hash, role, first_name, last_name, "
            "must_change_password, employee_id FROM users WHERE username = ?",
            (encrypt_username(username),),
        )
        user = c.fetchone()
        conn.close()

        if user:
            uid, enc_un, pw_hash, role, fn, ln, mcp, eid = user
            un = decrypt_username(enc_un)

            if verify_password(password, un, pw_hash):
                # ── successful login: reset failed attempts ──────────
                if username in _failed_attempts:
                    del _failed_attempts[username]

                _session.update(
                    logged_in=True, user_id=uid, username=un, role=role,
                    role_name=get_role_name(role), first_name=fn, last_name=ln,
                    must_change_password=bool(mcp), employee_id=eid,
                )
                log_activity(un, "Logged in")
                return True, f"Welcome {fn} {ln}!"

    # ── deny by default: anything that didn't pass gets rejected ─────
    _register_failed_attempt(username)

    # ── check if account is temporarily locked ───────────────────
    if username in _failed_attempts:
        info = _failed_attempts[username]
        if info["locked_until"] and datetime.now() < info["locked_until"]:
            remaining = (info["locked_until"] - datetime.now()).seconds // 60 + 1
            log_activity("unknown", "Login blocked",
                            f"Account '{username}' is locked ({remaining} min remaining)",
                            suspicious=True)
            return False, f"Account temporarily locked. Try again in {remaining} minute(s)."

    return False, "Invalid username or password."


def _register_failed_attempt(username):
    """Track failed login attempts and lock account after threshold."""
    if username not in _failed_attempts:
        _failed_attempts[username] = {"count": 0, "locked_until": None}

    _failed_attempts[username]["count"] += 1
    count = _failed_attempts[username]["count"]

    if count >= _LOCKOUT_THRESHOLD:
        _failed_attempts[username]["locked_until"] = datetime.now() + _LOCKOUT_DURATION
        log_activity("unknown", "Account locked",
                     f"Multiple failed login attempts for '{username}' "
                     f"({count} attempts)", suspicious=True)
    elif count > 1:
        log_activity("unknown", "Unsuccessful login",
                     f"Multiple attempts for '{username}' "
                     f"(attempt {count}/{_LOCKOUT_THRESHOLD})", suspicious=True)
    else:
        log_activity("unknown", "Unsuccessful login",
                     f"Failed login for '{username}'", suspicious=True)


def logout():
    if _session["logged_in"]:
        un = _session["username"]
        log_activity(un, "Logged out")
        _session.update(
            logged_in=False, user_id=None, username=None, role=None,
            role_name=None, first_name=None, last_name=None,
            must_change_password=False, employee_id=None,
        )
        return True, f"User {un} logged out."
    return False, "No user logged in."


# ── password change ──────────────────────────────────────────────────────
def update_password(old_password, new_password):
    if _session["logged_in"]:
        uid, un = _session["user_id"], _session["username"]
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE id = ?", (uid,))
        row = c.fetchone()

        if row and verify_password(old_password, un, row[0]):
            try:
                new_password = validate_password(new_password, un)
            except ValidationError as e:
                conn.close()
                return False, f"Invalid new password: {e}"

            if old_password != new_password:
                c.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                          (hash_password(new_password, un), uid))
                conn.commit()
                conn.close()
                _session["must_change_password"] = False
                log_activity(un, "Password updated")
                return True, "Password updated successfully."

            conn.close()
            return False, "New password must differ from current password."

        conn.close()
        if not row:
            return False, "User not found."
        log_activity(un, "Password change failed", "incorrect current password", suspicious=True)
        return False, "Incorrect current password."

    return False, "Not logged in."


# ── user lookup helpers ──────────────────────────────────────────────────
def get_user_by_username(username):
    try:
        username = validate_username(username)
    except ValidationError:
        return None

    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, username, role, first_name, last_name, created_at "
        "FROM users WHERE username = ?",
        (encrypt_username(username),),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0], "username": decrypt_username(row[1]),
        "role": row[2], "role_name": get_role_name(row[2]),
        "first_name": row[3], "last_name": row[4], "created_at": row[5],
    }


def list_users_by_role(role=None):
    conn = get_connection()
    c = conn.cursor()
    if role:
        c.execute("SELECT id, username, role, first_name, last_name, created_at "
                   "FROM users WHERE role = ? ORDER BY created_at DESC", (role,))
    else:
        c.execute("SELECT id, username, role, first_name, last_name, created_at "
                   "FROM users ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [
        {"id": r[0], "username": decrypt_username(r[1]), "role": r[2],
         "role_name": get_role_name(r[2]), "first_name": r[3],
         "last_name": r[4], "created_at": r[5]}
        for r in rows
    ]