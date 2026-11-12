from django.contrib.auth import login


class HeaderLoginMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = lookup_header_user(request)
        if user is not None:
            login(request, user)
        return self.get_response(request)


def lookup_header_user(request):
    return None
