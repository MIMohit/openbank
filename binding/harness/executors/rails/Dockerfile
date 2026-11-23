# syntax=docker/dockerfile:1
FROM ruby:3.3.14-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile ./
RUN bundle config set --local path /bundle && bundle install --jobs 4 && cp Gemfile.lock /Gemfile.lock.generated

FROM ruby:3.3.14-slim-bookworm
WORKDIR /app
COPY --from=build /bundle /bundle
COPY --from=build /Gemfile.lock.generated ./Gemfile.lock
COPY . .
RUN bundle config set --local path /bundle
ENV RAILS_ENV=production FRAMEWORK_TAG=rails OVERRIDE=off VERIFY_MODE=off
EXPOSE 8080
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb", "config.ru"]

# W15 ext-routes: ROUTES=v2 enables the richer v1 route space (build :v2 with --build-arg ROUTES=v2).
ARG ROUTES=off
ENV ROUTES=${ROUTES}
