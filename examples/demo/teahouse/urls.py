from django.urls import include, path

urlpatterns = [
    path("members/", include("members.urls")),
]
