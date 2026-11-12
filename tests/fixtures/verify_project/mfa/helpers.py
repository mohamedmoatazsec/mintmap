from django.contrib.auth import login

from acme_tokens import CodeBook, verify_blob


def load_book(user):
    return CodeBook(user.pk)


def confirm_link(user, token):
    return token == user.profile.link_token


def validate_audit_target(user):
    return user.is_active


def stamp_audit(user):
    validate_audit_target(user)  # outcome ignored: not treated as a check wrapper
    return None


def deep_inner(blob):
    if not verify_blob(blob):
        return False
    return True


def deep_mid(blob):
    if not deep_inner(blob):
        return False
    return True


def deep_outer(blob):
    if not deep_mid(blob):
        return False
    return True


def check_and_login(request, user):
    login(request, user)
