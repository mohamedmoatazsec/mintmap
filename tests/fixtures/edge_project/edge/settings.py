import os

INSTALLED_APPS = ["django.contrib.auth", "rest_framework", "rest_framework.authtoken", "edge", "api"]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "edge.middleware.HeaderLoginMiddleware",
]
if os.environ.get("EXTRA_MW"):
    MIDDLEWARE += [os.environ["EXTRA_MW"]]
AUTHENTICATION_BACKENDS = ["edge.backends.EmailBackend"]
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
}
ROOT_URLCONF = "edge.urls"
