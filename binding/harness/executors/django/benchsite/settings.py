"""Minimal API-only Django settings for the bench executor."""
import os

SECRET_KEY = "bench-executor-not-secret"
DEBUG = False
# Gateways may forward Host: api.bench.test or rewrite it to executor:8080; accept any.
ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "benchsite.urls"
USE_TZ = True
DATABASES = {}
OVERRIDE = os.environ.get("OVERRIDE", "off").lower() == "on"

INSTALLED_APPS = ["method_override"] if OVERRIDE else []

# Django's default MIDDLEWARE minus session/auth/messages/csrf/clickjacking (no DB, no cookies,
# token-authenticated API). CommonMiddleware is kept because it carries APPEND_SLASH (default True).
MIDDLEWARE = [
    "benchsite.middleware.BenchLogMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
]
if OVERRIDE:
    # django-method-override 1.0.4 (https://gitlab.com/localmed/django-method-override); README says
    # to place it after CsrfViewMiddleware, which is not installed here.
    MIDDLEWARE.append("method_override.middleware.MethodOverrideMiddleware")

LOGGING = {"version": 1, "disable_existing_loggers": True}
