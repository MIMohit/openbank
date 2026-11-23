#!/usr/bin/env bash
# Build bh-verifier:ablate (BIND_CLAIMS=full) and thin variant tags that only set env.
set -euo pipefail
A=$(cd "$(dirname "$0")/.." && pwd)
docker build -q -t bh-verifier:ablate "$A/verifier_ablate"
mk() { # tag BIND_CLAIMS QUERY_CANON
  printf 'FROM bh-verifier:ablate\nENV BIND_CLAIMS=%s QUERY_CANON=%s\n' "$2" "$3" | docker build -q -t "bh-verifier:ablate-$1" -
}
mk full        full            rfc3986
mk no-htm      no-htm          rfc3986
mk no-htu      no-htu          rfc3986
mk no-ath      no-ath          rfc3986
mk query       +query          rfc3986
mk digest      +digest         rfc3986
mk query-digest "+query,+digest" rfc3986
mk query-exact  +query         exact
mk query-sorted +query         sorted
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | grep 'bh-verifier:ablate'
