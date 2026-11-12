from django.urls import path

from . import views

localized_patterns = [path("shop/welcome/", views.welcome)]
urlpatterns = [path("shop/signin/", views.shop_signin)]
