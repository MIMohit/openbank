FROM python:3.12.16-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FRAMEWORK_TAG=django OVERRIDE=off VERIFY_MODE=off \
    DJANGO_SETTINGS_MODULE=benchsite.settings
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY benchsite ./benchsite
RUN mkdir -p /logs
EXPOSE 8080
# no access log (stdout carries only the JSONL lines); gunicorn defaults otherwise (header_map=drop, forwarded_allow_ips=127.0.0.1)
CMD ["gunicorn", "benchsite.wsgi:application", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4"]

# W15 ext-routes: ROUTES=v2 enables the richer v1 route space (build :v2 with --build-arg ROUTES=v2).
ARG ROUTES=off
ENV ROUTES=${ROUTES}
