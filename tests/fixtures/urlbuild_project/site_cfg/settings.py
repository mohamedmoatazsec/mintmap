"""Synthetic settings for the URL-construction fixture (P4/P5)."""
import os

SECRET_KEY = "fixture-not-secret"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.sessions",
    "web",
    "plugins.billing",
    "plugins.shop",
    "plugins.reports",
]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]

# The URLconf is chosen per process: both alternatives must be analysed.
ROOT_URLCONF = "site_cfg.urls"
if os.environ.get("SERVE_STREAMING"):
    ROOT_URLCONF = "site_cfg.stream_urls"

# URLconfs of these apps are mounted by a loop in site_cfg/urls.py
PLUGIN_APPS = ["plugins.billing", "plugins.shop"]
SHOW_LEGACY = os.environ.get("SHOW_LEGACY") == "1"
