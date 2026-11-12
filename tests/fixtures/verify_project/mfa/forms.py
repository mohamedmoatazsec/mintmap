"""Synthetic second-factor forms (written for MintMap tests)."""
from django import forms
from django.core.validators import validate_slug
from pyotp import TOTP

from acme_tokens import CodeBook


class OneTimeCodeForm(forms.Form):
    """A pyotp code checked inside a field clean method (catalog v2 check)."""

    code = forms.CharField()

    def __init__(self, generator: TOTP, data=None):
        self.generator = generator
        super().__init__(data)

    def clean_code(self):
        value = self.cleaned_data["code"]
        if not self.generator.verify(value, valid_window=1):
            raise forms.ValidationError("bad code")
        return value


class RecoveryCodeForm(forms.Form):
    """A verifier from a library MintMap does not know (acme_tokens)."""

    code = forms.CharField()

    def __init__(self, book: "CodeBook | None" = None, data=None):
        self.book = book
        super().__init__(data)

    def clean_code(self):
        value = self.cleaned_data["code"]
        if not self.book.check_code(value):
            raise forms.ValidationError("unknown code")
        return value


class PinForm(forms.Form):
    """Plain comparison: no verification-looking call at all."""

    pin = forms.CharField()

    def __init__(self, expected, data=None):
        self.expected = expected
        super().__init__(data)

    def clean_pin(self):
        if self.cleaned_data["pin"] != self.expected:
            raise forms.ValidationError("wrong pin")
        return self.cleaned_data["pin"]


class NicknameForm(forms.Form):
    nickname = forms.CharField()

    def clean_nickname(self):
        validate_slug(self.cleaned_data["nickname"])  # input-format validator, not a credential check
        return self.cleaned_data["nickname"]
