"""Project URL helper functions (they build path() objects for the URLconf)."""
from django.urls import path

from web.dispatch import by_method
from web.views import redirect_view


def page(route, view, name=None):
    return path(route, view, name=name)


def endpoint(route, **handlers):
    # the views are passed to the dispatcher in the route's extra kwargs
    return path(route, by_method, handlers)


def mirrored(route, view):
    out = []
    for version in ("v1", "v2"):
        out.append(path(f"{version}/{route}", view))
    return out


def add_status_routes(patterns):
    # modifies the caller's list in place
    patterns.append(path("status/", redirect_view))
