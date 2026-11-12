from django.urls import path

from . import views

urlpatterns = [
    path("login/password/", views.password_login, name="password-login"),
    path("login/otp-ignored/", views.otp_login_ignored, name="otp-ignored"),
    path("login/otp/", views.otp_login_wrapper, name="otp-login"),
    path("login/email/", views.EmailLoginView.as_view(), name="email-login"),
    path("login/async/", views.async_login, name="async-login"),
]
