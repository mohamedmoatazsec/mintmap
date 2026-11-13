"""Settings of the Teahouse demo. Not a deployable configuration."""
SECRET_KEY = "demo-only-not-a-secret"
DEBUG = False
ALLOWED_HOSTS = ["teahouse.example"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "rest_framework.authtoken",
    "members",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

ROOT_URLCONF = "teahouse.urls"

AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.TokenAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}

SESSION_COOKIE_SECURE = True
PASSWORD_RESET_TIMEOUT = 60 * 60
