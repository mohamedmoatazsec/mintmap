from django.urls import path

from web import views

urlpatterns = [path("stream/signin/", views.stream_signin)]
