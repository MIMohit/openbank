<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class BenchController
{
    private static function env(string $k, string $d): string
    {
        $v = getenv($k);
        return ($v === false || $v === '') ? $d : $v;
    }

    private static function encSegment(string $s): string
    {
        // interpretation #6: unreserved + sub-delims + ':' '@' literal (Python quote safe="-._~!$&'()*+,;=:@")
        return preg_replace_callback('/[^A-Za-z0-9\-._~!$&\'()*+,;=:@]/', fn ($m) => sprintf('%%%02X', ord($m[0])), $s);
    }

    private function op(Request $r, string $opId, string $template, array $params = []): JsonResponse
    {
        $params = array_map('strval', $params);
        $r->attributes->set('bench.op_id', $opId);
        $r->attributes->set('bench.route_template', $template);
        $r->attributes->set('bench.path_params', $params);
        $fw = self::env('FRAMEWORK_TAG', 'laravel');
        $mode = self::env('VERIFY_MODE', 'off');
        if ($mode !== 'off') {
            if ($mode === 'origin-routed') {
                $method = $r->getMethod();
                $uri = $template;
                foreach ($params as $k => $v) {
                    $uri = str_replace('{'.$k.'}', self::encSegment($v), $uri);
                }
            } else {
                $method = (string) $r->server->get('REQUEST_METHOD', $r->getRealMethod()); // raw token as received
                $uri = $r->server->get('REQUEST_URI', '');
            }
            $headers = ['X-Original-Method' => $method, 'X-Original-URI' => $uri,
                        'X-Original-Host' => (string) $r->headers->get('Host', '')];
            foreach (['Authorization', 'DPoP'] as $h) {
                if ($r->headers->has($h)) {
                    $headers[$h] = $r->headers->get($h);
                }
            }
            try {
                $resp = Http::withHeaders($headers)->connectTimeout(3)->timeout(5)
                    ->get(self::env('VERIFIER_URL', 'http://verifier:9100/authz/orig'));
                $allow = $resp->successful();
            } catch (\Throwable $e) {
                $allow = false; // fail closed
            }
            if (! $allow) {
                $r->attributes->set('bench.denied', true);
                return new JsonResponse(['op_id' => $opId, 'framework' => $fw, 'denied' => true], 401);
            }
        }
        return new JsonResponse(['op_id' => $opId, 'framework' => $fw, 'method' => $r->getMethod(),
            'path_params' => (object) $params], 200, [], JSON_UNESCAPED_SLASHES);
    }

    public function listAccounts(Request $r) { return $this->op($r, 'listAccounts', '/api/v1/accounts'); }
    public function getAccount(Request $r, string $id) { return $this->op($r, 'getAccount', '/api/v1/accounts/{id}', ['id' => $id]); }
    public function updateAccount(Request $r, string $id) { return $this->op($r, 'updateAccount', '/api/v1/accounts/{id}', ['id' => $id]); }
    public function deleteAccount(Request $r, string $id) { return $this->op($r, 'deleteAccount', '/api/v1/accounts/{id}', ['id' => $id]); }

    // G1 query dispatch, idiomatic $request->input('op') (Laravel merges body input over the query).
    public function accountAction(Request $r, string $id)
    {
        $op = $r->input('op');
        $opId = $op === 'freeze' ? 'accountAction.freeze' : ($op === 'close' ? 'accountAction.close' : 'accountAction.unknown');
        return $this->op($r, $opId, '/api/v1/accounts/{id}/actions', ['id' => $id]);
    }

    public function createTransfer(Request $r) { return $this->op($r, 'createTransfer', '/api/v1/transfers'); }

    // G1 body dispatch: the raw body is parsed as JSON whatever the Content-Type.
    public function graphql(Request $r)
    {
        $obj = json_decode((string) $r->getContent(), true);
        $name = is_array($obj) && isset($obj['operationName']) && is_string($obj['operationName']) ? $obj['operationName'] : null;
        $opId = $name === 'getProfile' ? 'graphql.getProfile' : ($name === 'deleteProfile' ? 'graphql.deleteProfile' : 'graphql.unknown');
        return $this->op($r, $opId, '/api/v1/graphql');
    }

    public function me(Request $r) { return $this->op($r, 'me', '/api/v1/me'); }
    public function adminListUsers(Request $r) { return $this->op($r, 'adminListUsers', '/api/v1/admin/users'); }
    public function adminDeleteUser(Request $r, string $id) { return $this->op($r, 'adminDeleteUser', '/api/v1/admin/users/{id}', ['id' => $id]); }
    public function health(Request $r) { return $this->op($r, 'health', '/api/v1/health'); }
    public function publicFile(Request $r, string $file) { return $this->op($r, 'publicFile', '/api/v1/public/{file}', ['file' => $file]); }
    public function getAccountV2(Request $r, string $id) { return $this->op($r, 'getAccountV2', '/api/v2/accounts/{id}', ['id' => $id]); }

    // ROUTES=v2 actions (reachable only when the v2 routes are wired up; see routes/bench.php).
    public function postAccount(Request $r, string $id) { return $this->op($r, 'postAccount', '/api/v1/accounts/{id}', ['id' => $id]); }
    public function getStatements(Request $r, string $id) { return $this->op($r, 'getStatements', '/api/v1/accounts/{id}/statements', ['id' => $id]); }
    public function deleteStatement(Request $r, string $id, string $sid) { return $this->op($r, 'deleteStatement', '/api/v1/accounts/{id}/statements/{sid}', ['id' => $id, 'sid' => $sid]); }
    public function catchAllFile(Request $r, string $path) { return $this->op($r, 'catchAllFile', '/api/v1/files/{path}', ['path' => $path]); }
}
