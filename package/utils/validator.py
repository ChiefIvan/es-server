from re import compile


def validate_entries(entries, allowed_fields=None):
    for key, value in entries.items():
        if allowed_fields and key in allowed_fields and (value is None or (isinstance(value, str) and len(value.strip()) == 0)):
            return {"msg": f"Don't leave the {key} input empty!"}

    is_email_format_valid = validate_email_format(entries["email"])
    if is_email_format_valid is not None:
        return is_email_format_valid
    
    is_id_format_valid = validate_id(entries["_id"])
    if is_id_format_valid is not None:
        return is_id_format_valid

    is_password_string_valid = validate_password(
        entries["password"], entries["password_confirm"])
    if is_password_string_valid is not None:
        return is_password_string_valid

    return None


def validate_email_format(email):
    pattern = compile(
        r"^[a-zA-Z0-9._%+-]{5,}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    if not isinstance(email, str) or not pattern.match(email):
        return {"msg": "Incorrect Email format!"}

    return None

def validate_id(id):
    pattern = compile(r"^[0-9]{4}-[0-9]{4}$")

    if not isinstance(id, str) or not pattern.match(id):
        return {"msg": "ID must be in format XXXX-XXXX!"}

    return None


def validate_password(password, password_confirm):
    pattern = compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).*$")

    if not isinstance(password, str) or not isinstance(password_confirm, str):
        return {"msg": "Password must be a string!"}

    if len(password) < 8 or len(password) > 16:
        return {"msg": "Your password must be between 8 and 12 characters long!"}

    if not pattern.match(password):
        return {"msg": "Your Password must contain atleast 1 Uppercase, 1 Lowercase and a Number!"}

    if password != password_confirm:
        return {"msg": "Your Password and Password (Confirm) must be the same!"}

    return None
