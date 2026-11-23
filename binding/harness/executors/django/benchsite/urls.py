import os

from django.urls import include, path

from . import views

handler404 = "benchsite.views.not_found"

urlpatterns = [
    path("api/v1/accounts", views.Accounts.as_view()),
    path("api/v1/accounts/<str:id>", views.Account.as_view()),
    path("api/v1/accounts/<str:id>/actions", views.AccountAction.as_view()),
    path("api/v1/transfers", views.Transfers.as_view()),
    path("api/v1/graphql", views.GraphQL.as_view()),
    path("api/v1/me", views.Me.as_view()),
    path("api/v1/admin/users", views.AdminUsers.as_view()),
    path("api/v1/admin/users/<str:id>", views.AdminUser.as_view()),
    path("api/v1/health", views.Health.as_view()),
    path("api/v1/public/<str:file>", views.PublicFile.as_view()),
    # Prefix mount: an included URLconf under api/v2/
    path("api/v2/", include("benchsite.v2urls")),
]

if os.environ.get("ROUTES", "off").lower() == "v2":
    # Nested same-method routes, nested DELETE, and a catch-all (Django `path:` matches '/').
    urlpatterns[3:3] = [
        path("api/v1/accounts/<str:id>/statements", views.AccountStatements.as_view()),
        path("api/v1/accounts/<str:id>/statements/<str:sid>", views.AccountStatement.as_view()),
        path("api/v1/files/<path:path>", views.CatchAllFile.as_view()),
    ]
