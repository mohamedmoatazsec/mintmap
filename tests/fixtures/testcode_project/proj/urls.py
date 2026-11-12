from django.urls import path

from shop import views

urlpatterns = [
    path("enter/", views.enter),
]
