from django.urls import path

from . import views

urlpatterns = [
    path("accounts/<str:id>", views.AccountV2.as_view()),
]
