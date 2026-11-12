from django.http import HttpResponseNotAllowed


def by_method(request, **handlers):
    handler = handlers.get(request.method)
    if handler is None:
        return HttpResponseNotAllowed(list(handlers))
    return handler(request)
