from django.contrib.auth import login


def on_external_event(sender, request, user, **kwargs):
    login(request, user)


def run_pipeline(backend, login, user):
    # social-core style: the login function arrives as a parameter
    return login(backend, user)
