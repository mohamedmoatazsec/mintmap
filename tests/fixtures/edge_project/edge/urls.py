from django.contrib.auth import views as auth_views
from django.urls import include, path, re_path

from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from api.views import JwtLogin, TokenLogin
from api.viewsets import SessionViewSet
from edge import views
from edge.auth_views import AuditedLogin, PlainLogin, exchange_view

router = DefaultRouter()
router.register(r"sessions", SessionViewSet, basename="session")

urlpatterns = [
    path("wrong-user/<int:target>/", views.wrong_user),
    path("disjunction/", views.disjunction),
    path("assert/", views.assert_only),
    path("tuple/", views.tuple_truthy),
    path("after/", views.check_after_mint),
    path("swallowed/", views.swallowed),
    path("backend/", views.backend_login),
    path("walrus/", views.walrus_login),
    path("invite/", views.invite),
    path("stale/", views.stale_result),
    path("api/token/", TokenLogin.as_view()),
    path("api/jwt/", JwtLogin.as_view()),
    path("reset/<uidb64>/<token>/", auth_views.PasswordResetConfirmView.as_view(post_reset_login=True)),
    path("reset-plain/<uidb64>/<token>/", auth_views.PasswordResetConfirmView.as_view()),
    path("thirdparty/", include("someunknownlib.urls")),
    re_path(r"^dyn/", make_patterns()),
    path("api/token-auth/", obtain_auth_token),
    path("api/jwt/refresh/", TokenRefreshView.as_view()),
    path("login/plain/", PlainLogin.as_view()),
    path("login/audited/", AuditedLogin.as_view()),
    path("exchange/", exchange_view),
    path("api/", include(router.urls)),
]
