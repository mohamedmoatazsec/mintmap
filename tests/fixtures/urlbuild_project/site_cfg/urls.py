"""URL list built step by step (P4) with first-match shadowing cases (P5)."""
from django.conf import settings
from django.conf.urls.i18n import i18n_patterns
from django.contrib import admin
from django.contrib.auth.views import LoginView
from django.urls import include, path, re_path
from django.utils.module_loading import import_string

from plugins.reports.urls import bundle as report_bundle
from site_cfg.urlkit import add_status_routes, endpoint, mirrored, page
from urlplugins_lib import attach_plugin_routes
from web import views

localized = [
    page("signin/", views.password_signin, name="signin"),
    # same literal route: only reverse() uses it, the line above always matches first
    path("signin/", LoginView.as_view(), name="signin-reverse"),
    page("welcome/login/", views.page_with_library_login),
]

api = [
    endpoint("token/", POST=views.token_signin),
]
api += mirrored("sso/", views.sso_signin)

routes = list(localized)                 # a copy: later additions to `localized` are not in `routes`
routes += [path("api/", include(api))]   # include() keeps the list object: later additions are routed
api.append(page("late/", views.late_signin))
localized.append(page("localized-only/", views.localized_only_signin))
routes.extend([page("magic/<str:key>/", views.magic_signin)])
routes.insert(0, path("admin/login/", views.password_signin))
routes += [path("admin/", admin.site.urls)]
routes += [path("accounts/", include("django.contrib.auth.urls"))]
routes += [path("accounts/login/", views.custom_account_login)]
routes += [path("", include(report_bundle))]

for plugin in settings.PLUGIN_APPS:
    routes += [path("", include(f"{plugin}.urls"))]
    localized += import_string(f"{plugin}.urls.localized_patterns")

if settings.SHOW_LEGACY:
    routes += [page("legacy/", views.legacy_signin_a)]
routes += [page("legacy/", views.legacy_signin_b)]

routes += [page("beta/", views.beta_signin)] if settings.SHOW_LEGACY else []
routes += [path("choose/", views.choice_a if settings.SHOW_LEGACY else views.choice_b)]

routes += [path(f"{name}/", views.named_signin) for name in ("north", "south")]
routes += [path(r.old, views.redirect_view) for r in settings.REDIRECT_RULES]
for extra in sorted(settings.EXTRA_ROUTES):
    routes += [path(extra, views.redirect_view)]

prefix = ""
if settings.SHOW_LEGACY:
    prefix = "old/"
routes += [path(f"{prefix}portal/", views.portal_signin), path(f"{prefix}portal/", views.second_portal_signin)]
routes += [path("u/<int:pk>/signin/", views.user_signin), path("u/<int:uid>/signin/", views.user_signin_dup)]
routes += [path("x/signin", views.slash_a), path("x/signin/", views.slash_b)]
routes += [re_path(r"^r/signin/$", views.regex_a), path("r/signin/", views.regex_b)]

add_status_routes(routes)
attach_plugin_routes(routes)

urlpatterns = i18n_patterns(*localized) + routes
