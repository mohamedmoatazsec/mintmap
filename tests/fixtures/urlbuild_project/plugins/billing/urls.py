from django.urls import path

from . import views

localized_patterns = [path("billing/welcome/", views.welcome)]
urlpatterns = [path("billing/signin/", views.billing_signin)]
