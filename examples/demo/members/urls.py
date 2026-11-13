from django.urls import path

from . import views

urlpatterns = [
    path("sign-in/", views.sign_in, name="sign-in"),
    path("sign-in/code/", views.sign_in_code, name="sign-in-code"),
    path("reset/<uidb64>/<token>/", views.finish_reset, name="finish-reset"),
    path("api/token/", views.ApiTokenView.as_view(), name="api-token"),
]
