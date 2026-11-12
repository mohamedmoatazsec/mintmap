from django.urls import include, path

urlpatterns = [
    path("mfa/", include("mfa.urls")),
]
