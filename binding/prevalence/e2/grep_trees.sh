#!/bin/sh
# Negative-result check: search the pinned source trees of frameworks WITHOUT a documented
# built-in method override for any override mechanism.  Run from binding/prevalence/.
# Trees: data/e2_trees/<name> (tarballs of the release tags; see E2_results.md for the refs).
PAT='method[-_ ]\?override\|methodoverride\|x-http-method\|\b_method\b\|X-METHOD'
for t in data/e2_trees/*/; do t=${t%/}
  echo "== $t"
  grep -rIn -i "$PAT" "$t" --include='*.py' --include='*.go' 2>/dev/null | grep -v -i '/tests\?/\|_test\.go\|/docs/' | head -20
  echo "  (non-test source hits: $(grep -rIl -i "$PAT" "$t" --include='*.py' --include='*.go' 2>/dev/null | grep -v -i '/tests\?/\|_test\.go\|/docs/' | wc -l | tr -d ' ') files)"
done
