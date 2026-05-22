"""
input_handlers.py – Console input prompts with validation loops and exit support.

All prompt functions loop until the user provides valid input or types 'exit'/'cancel'.
"""

import re
import getpass
from validation import (
    ValidationError, _check_null_bytes,
    is_valid_username, is_valid_password,
)


class CancelInputException(Exception):
    """Raised when user types 'exit' or 'cancel' to abort."""


_EXIT_WORDS = {"exit", "cancel"}


def _is_exit(value):
    return value in _EXIT_WORDS


# ── generic prompts ──────────────────────────────────────────────────────
def prompt_with_validation(prompt_text, validator_func, allow_exit=True, mask=False):
    """Keep asking until validator passes (or user exits).

    When *mask* is True the input is read with getpass so it is not echoed.
    """
    while True:
        value = getpass.getpass(prompt_text) if mask else input(prompt_text)
        if allow_exit and _is_exit(value):
            raise CancelInputException()
        try:
            return validator_func(value)
        except ValidationError as e:
            print(f"  Error: {e}\n")


def prompt_integer_with_validation(prompt_text, validator_func, allow_exit=True): # wordt niet gebruikt
    while True:
        value = input(prompt_text)
        if allow_exit and _is_exit(value):
            raise CancelInputException()
        try:
            return validator_func(value)
        except ValidationError as e:
            print(f"  Error: {e}\n")
        except ValueError:
            print("  Error: Please enter a valid number.\n")


def prompt_password_with_confirmation(prompt_text, validator_func,
                                      current_password=None, allow_exit=True):
    """Prompt for password + confirmation. Optionally reject reuse of current_password."""
    while True:
        pw = prompt_with_validation(prompt_text, validator_func, allow_exit, mask=True)
        if current_password and pw == current_password:
            print("\n  New password must differ from the current one. Try again.\n")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if allow_exit and _is_exit(confirm):
            raise CancelInputException()
        if not confirm:
            print("\n  Confirmation cannot be empty. Try again.\n")
        elif pw != confirm:
            print("\n  Passwords do not match. Try again.\n")
        else:
            return pw


# ── menu & choice prompts ────────────────────────────────────────────────
def prompt_menu_choice(prompt_text, min_choice, max_choice, allow_exit=True):
    while True:
        value = input(prompt_text)
        if allow_exit and _is_exit(value):
            raise CancelInputException()
        try:
            n = int(value)
            if min_choice <= n <= max_choice:
                return value
        except ValueError:
            pass
        print("  Invalid choice.\n")


def prompt_confirmation(prompt_text, allow_exit=True):
    """Return True for 'yes', False for 'no'."""
    while True:
        value = input(prompt_text)
        try:
            _check_null_bytes(value, "Confirmation")
        except ValidationError:
            print("  Invalid input.\n")
            continue
        if allow_exit and _is_exit(value):
            raise CancelInputException()
        if value == "yes":
            return True
        if value == "no":
            return False
        print("  Please enter 'yes' or 'no'.\n")


def prompt_optional_field(prompt_text, validator_func, current_value=None, allow_exit=True):
    """Prompt for an optional update. Press Enter to skip."""
    suffix = f" [{current_value}]" if current_value else ""
    full = f"{prompt_text}{suffix} (Enter to skip): "
    while True:
        value = input(full)
        if not value:
            return None
        if allow_exit and _is_exit(value):
            raise CancelInputException()
        try:
            return validator_func(value)
        except ValidationError as e:
            print(f"  Error: {e}\n")


def prompt_choice_from_list(prompt_text, options, allow_exit=True):
    """Display numbered list, return chosen option string."""
    print(f"\n{prompt_text}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    choice = prompt_menu_choice(f"Enter choice (1-{len(options)}): ", 1, len(options), allow_exit)
    return options[int(choice) - 1]


# ── UI-layer quick validators ────────────────────────────────────────────
def validate_username_input(username):
    return is_valid_username(username, allow_super_admin=True)


def validate_password_input(password, username=""):
    return is_valid_password(password, username)


def validate_number_input(choice, length):
    if not isinstance(choice, str):
        return False
    try:
        _check_null_bytes(choice, "Menu choice")
    except ValidationError:
        return False
    return choice in [str(i) for i in range(1, length + 1)]
  

def validate_restore_code_input(code):
    if not isinstance(code, str):
        return False
    try:
        _check_null_bytes(code, "Restore code")
    except ValidationError:
        return False
    return bool(re.match(r"^[A-Z0-9]{12}$", code))