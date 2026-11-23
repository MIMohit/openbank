#!/bin/sh
# Download release-tag tarballs of the frameworks without a built-in override, for grep_trees.sh.
# Run from binding/prevalence/.  Lands in data/e2_trees/ (gitignored).
set -eu
mkdir -p data/e2_trees
fetch() { # repo tag dirname
  [ -n "$(ls -A "data/e2_trees/$3" 2>/dev/null)" ] && return 0
  mkdir -p "data/e2_trees/$3"
  curl -sfL "https://codeload.github.com/$1/tar.gz/refs/tags/$2" | tar -xz -C "data/e2_trees/$3" --strip-components 1
  echo "$1@$2 $(date -u +%FT%TZ)" > "data/e2_trees/$3.fetched"
}
fetch django/django 6.1.3 django_django-6.1.3
fetch fastapi/fastapi 0.165.0 fastapi_fastapi0.165.0
fetch go-chi/chi v5.5.0 go-chi_chiv5.5.0
fetch Kludex/starlette 1.10.0 Kludex_starlette1.10.0
