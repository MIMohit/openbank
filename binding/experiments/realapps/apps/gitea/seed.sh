#!/usr/bin/env bash
# Seed a running w22-gitea-app (fresh /data volume) with users alice(admin)+bob and public repos.
# Idempotent-ish: ignores "already exists". Run after the app container is healthy.
set -u
C=w22-gitea-app
G(){ docker exec $C curl -s "$@"; }
docker exec -u git $C gitea admin user create --admin --username alice --password 'Alice-pw-123' --email alice@bench.test --must-change-password=false 2>&1 | tail -1
docker exec -u git $C gitea admin user create --username bob --password 'Bob-pw-12345' --email bob@bench.test --must-change-password=false 2>&1 | tail -1
TOK=$(G -u alice:Alice-pw-123 -X POST http://localhost:3000/api/v1/users/alice/tokens -H 'Content-Type: application/json' -d '{"name":"w22s","scopes":["all"]}' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("sha1",""))' 2>/dev/null)
G -u alice:Alice-pw-123 -X POST http://localhost:3000/api/v1/user/repos -H 'Content-Type: application/json' -d '{"name":"demo","private":false,"auto_init":true,"description":"alice demo repo"}' -o /dev/null -w 'create alice/demo: %{http_code}\n'
G -H "Authorization: token $TOK" -X POST http://localhost:3000/api/v1/repos/alice/demo/issues -H 'Content-Type: application/json' -d '{"title":"first issue","body":"hello"}' -o /dev/null -w 'create issue: %{http_code}\n'
TOKB=$(G -u bob:Bob-pw-12345 -X POST http://localhost:3000/api/v1/users/bob/tokens -H 'Content-Type: application/json' -d '{"name":"w22sb","scopes":["all"]}' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("sha1",""))' 2>/dev/null)
G -H "Authorization: token $TOKB" -X POST http://localhost:3000/api/v1/user/repos -H 'Content-Type: application/json' -d '{"name":"public-b","private":false,"auto_init":true,"description":"bob public repo"}' -o /dev/null -w 'create bob/public-b: %{http_code}\n'
echo "--- verify public routes direct ---"
for p in /api/v1/repos/alice/demo /api/v1/repos/alice/demo/issues /api/v1/repos/bob/public-b; do
  echo -n "$p -> "; G -o /dev/null -w '%{http_code}\n' "http://localhost:3000$p"
done
