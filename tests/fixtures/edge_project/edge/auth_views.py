from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.http import HttpResponse
from rest_framework_simplejwt.tokens import RefreshToken


class PlainLogin(auth_views.LoginView):
    template_name = "plain.html"


class AuditedLogin(auth_views.LoginView):
    def form_valid(self, form):
        record(form.get_user())
        return super().form_valid(form)


def record(user):
    return None


@login_required
def exchange_view(request):
    refresh = RefreshToken.for_user(request.user)
    link = signing.dumps({"uid": request.user.pk})
    return HttpResponse(f"{refresh} {link}")
