# syntax=docker/dockerfile:1
FROM dunglas/frankenphp:1.14.0-php8.3-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends unzip git && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2.11.2 /usr/bin/composer /usr/bin/composer
WORKDIR /build
RUN composer create-project --no-interaction --prefer-dist --no-dev laravel/laravel:12.12.2 app \
 && cd app && composer require --no-interaction --update-no-dev laravel/framework:12.73.0 \
 && composer show -i | grep -E '^(laravel/framework|symfony/http-foundation|symfony/routing) ' > /build/app/VERSIONS.txt
COPY overlay/ /build/app/
RUN cd app && php artisan --version >> VERSIONS.txt && php -v | head -1 >> VERSIONS.txt

FROM dunglas/frankenphp:1.14.0-php8.3-bookworm
COPY --from=build /build/app /app
COPY Caddyfile /etc/frankenphp/Caddyfile
WORKDIR /app
# The frankenphp base image ships HEALTHCHECK `curl http://localhost:2019/metrics`
# (the Caddy admin endpoint). Our Caddyfile sets `admin off`, so port 2019 is closed and
# that inherited healthcheck can NEVER pass -> the container is reported unhealthy and
# `docker compose up --wait` fails for every laravel topology. Readiness is validated
# end-to-end by the orchestrator's `probe` sidecar (W6), not by this. Disable it. (W15)
HEALTHCHECK NONE
ENV FRAMEWORK_TAG=laravel OVERRIDE=off VERIFY_MODE=off APP_ENV=production APP_DEBUG=false \
    LOG_CHANNEL=stderr SERVER_NAME=:8080
EXPOSE 8080
CMD ["frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"]

# W15 ext-routes: ROUTES=v2 enables the richer v1 route space (build :v2 with --build-arg ROUTES=v2).
ARG ROUTES=off
ENV ROUTES=${ROUTES}
