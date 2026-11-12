SECRET_KEY = "fixture-not-secret"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "rest_framework", "mfa"]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
ROOT_URLCONF = "proj.urls"
