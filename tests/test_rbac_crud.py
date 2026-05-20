"""Role-based CRUD, salary-batch lock, and SQL-injection safety (B1)."""

import auth
from claims import add_claim, update_claim, approve_claim, search_claims
from employees import update_employee, get_employee_by_id, search_employees
from users import create_manager, update_user_profile

EMP_PW = "Employee_pas1!"
SUPER = ("super_admin", "Admin_123?")


# ── claims: employee lifecycle ─────────────────────────────────────────────
def test_employee_can_add_and_search_own_claim(employee):
    emp_user, _ = employee
    auth.login(emp_user, EMP_PW)
    ok, msg = add_claim("2026-05-15", "123456", "Home Office")
    assert ok, msg
    assert search_claims("123456"), "employee should find own claim"


def test_employee_cannot_approve_claim(employee):
    emp_user, _ = employee
    auth.login(emp_user, EMP_PW)
    add_claim("2026-05-15", "123456", "Home Office")
    cid = search_claims("123456")[0]["id"]
    ok, msg = approve_claim(cid, "2026-07")
    assert not ok


def test_salary_batch_locks_employee_edit(employee):
    emp_user, _ = employee
    auth.login(emp_user, EMP_PW)
    add_claim("2026-05-15", "123456", "Home Office")
    cid = search_claims("123456")[0]["id"]
    auth.logout()

    auth.login(*SUPER)               # approve assigns a salary batch
    ok, msg = approve_claim(cid, "2026-07")
    assert ok, msg
    auth.logout()

    auth.login(emp_user, EMP_PW)     # now locked for the employee
    ok, msg = update_claim(cid, project_number="999")
    assert not ok
    assert "salary batch" in msg.lower()


# ── users / RBAC ───────────────────────────────────────────────────────────
def test_employee_cannot_create_manager(employee):
    emp_user, _ = employee
    auth.login(emp_user, EMP_PW)
    ok, msg, _ = create_manager("xmgruser1", "A", "Bee", password="Manager_pass1!")
    assert not ok


def test_super_admin_updates_manager_profile(manager):
    auth.login(*SUPER)               # manager fixture left us logged out
    ok, msg = update_user_profile("mgruser01", first_name="Megan")
    assert ok, msg


# ── SQL-injection safety (B1 column whitelist + parameterised values) ──────
def test_update_employee_rejects_malicious_column(employee):
    _, eid = employee
    auth.login(*SUPER)
    payload = {"first_name = '' ; DROP TABLE employees;--": "x"}
    ok, msg = update_employee(eid, **payload)
    assert not ok
    assert get_employee_by_id(eid) is not None   # table + row survive


def test_update_employee_rejects_injection_value(employee):
    _, eid = employee
    auth.login(*SUPER)
    ok, msg = update_employee(eid, street_name="'; DROP TABLE employees;--")
    assert not ok                                 # blocked by validation
    assert get_employee_by_id(eid) is not None


def test_search_with_injection_string_is_safe(employee):
    auth.login(*SUPER)
    res = search_employees("' OR '1'='1")
    assert isinstance(res, list)                  # no crash, no SQL executed
