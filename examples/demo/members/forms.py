import pyotp
from django import forms


class SignInForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)


class CodeForm(forms.Form):
    """The six-digit code from the member's authenticator app."""

    code = forms.CharField(min_length=6, max_length=6)

    def __init__(self, seed, data=None):
        self.totp = pyotp.TOTP(seed)
        super().__init__(data)

    def clean_code(self):
        code = self.cleaned_data["code"]
        if not self.totp.verify(code, valid_window=1):
            raise forms.ValidationError("That code is not valid.")
        return code


class NewPasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput, min_length=12)
