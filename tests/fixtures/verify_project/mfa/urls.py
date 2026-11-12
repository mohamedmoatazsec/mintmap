from django.urls import path

from . import views

urlpatterns = [
    path("totp/", views.totp_step),
    path("recovery/", views.recovery_step),
    path("pin/", views.pin_step),
    path("key/", views.key_step),
    path("ledger/", views.ledger_step),
    path("link/<str:token>/", views.link_step),
    path("remote/", views.remote_token_step),
    path("unsafe/", views.unsafe_token_step),
    path("signed/<str:blob>/", views.signed_link_step),
    path("audited/", views.audited_step),
    path("deep/", views.deep_step),
    path("mid/", views.mid_step),
    path("wrapped/", views.wrapped_step),
    path("api/pin-token/", views.PinTokenView.as_view()),
]
