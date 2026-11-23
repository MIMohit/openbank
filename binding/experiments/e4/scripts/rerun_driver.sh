#!/usr/bin/env bash
# Rerun one representative topology per independent class, 3x on fresh topologies each.
# Serial: one topology up at a time (CONTRACT). Run from binding/harness.
set -uo pipefail
REPS=${1:-3}
declare -a R=(
  "framework:aspnet:dot-segment            w12-allow-ngx-aspnet-def"
  "gateway:kong:dot-segment                w12-allow-kng-fastapi-def"
  "framework:aspnet:case-fold              w12-block-ngx-aspnet-def"
  "framework:express:case-fold             w12-block-ngx-express-def"
  "framework:rails:double-slash            w12-block-ngx-rails-def"
  "framework:spring:matrix-param           w12-block-ngx-spring-def"
  "gateway:kong:double-slash               w12-block-kng-spring-def"
)
echo "RERUN DRIVER start $(date +%H:%M:%S)  reps=$REPS"
for row in "${R[@]}"; do
  cls=$(echo "$row" | awk '{print $1}'); id=$(echo "$row" | awk '{print $2}')
  echo "=== [$cls] $id ==="
  bash ../experiments/e4/scripts/rerun_e4.sh "$id" "$REPS" 2>&1
done
echo "RERUN DRIVER done $(date +%H:%M:%S)"
