from django.urls import path

from . import views

# include() accepts a (patterns, app_name) tuple
bundle = ([path("reports/signin/", views.reports_signin)], "reports")
