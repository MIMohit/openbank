#!/bin/sh
# Re-download every pinned framework source file listed in e2/pins.tsv from
# raw.githubusercontent.com at its tag and compare it byte-for-byte with data/e2_sources/.
# Usage: sh e2/verify_pins.sh <empty scratch dir>   (run from binding/prevalence/)
set -u
D=${1:?scratch dir}
tail -n +2 e2/pins.tsv | while IFS="$(printf '\t')" read -r f repo ref path; do
  url="https://raw.githubusercontent.com/$repo/$ref/$path"
  if curl -sfL "$url" -o "$D/$f"; then
    if cmp -s "$D/$f" "data/e2_sources/$f"; then r=IDENTICAL; else r=DIFFERS; fi
  else r=FETCH_FAILED; fi
  printf '%s\t%s\t%s\n' "$r" "$f" "$url"
done
