<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/** Outermost global middleware: NOT_FOUND mapping and one JSON log line per request (CONTRACT §3). */
class BenchLog
{
    private const TRUST = ['x-forwarded-', 'x-original-', 'x-verified-', 'x-client-cert', 'client-cert',
                           'x-forwarded-client-cert', 'x-auth-'];

    public static function jti(?string $dpop): ?string
    {
        if ($dpop === null || $dpop === '') return null;
        $parts = explode('.', trim($dpop));
        if (count($parts) < 2) return null;
        $raw = base64_decode(strtr($parts[1], '-_', '+/'), true);
        if ($raw === false) return null;
        $obj = json_decode($raw, true);
        return (is_array($obj) && isset($obj['jti']) && is_string($obj['jti'])) ? $obj['jti'] : null;
    }

    public function handle(Request $request, Closure $next)
    {
        $fw = getenv('FRAMEWORK_TAG') ?: 'laravel';
        $rawMethod = (string) $request->server->get('REQUEST_METHOD', $request->getRealMethod()); // exact token (getRealMethod() upper-cases)
        // FrankenPHP sets REQUEST_URI to the request-target as received.
        $rawTarget = (string) $request->server->get('REQUEST_URI', '');
        $response = $next($request);
        $status = $response->getStatusCode();
        if (! $request->attributes->has('bench.op_id') && in_array($status, [404, 405], true)) {
            $response = new JsonResponse(['op_id' => 'NOT_FOUND', 'framework' => $fw,
                'method' => $request->getMethod(), 'path_params' => new \stdClass()], 404);
            $status = 404;
        }
        $trust = [];
        foreach ($request->headers->all() as $name => $values) {
            $lower = strtolower($name);
            foreach (self::TRUST as $p) {
                if (str_starts_with($lower, $p)) { $trust[$lower] = implode(', ', $values); break; }
            }
        }
        $qi = strpos($rawTarget, '?');
        $rec = [
            'ts' => gmdate('Y-m-d\TH:i:s').sprintf('.%03dZ', (int) (fmod(microtime(true), 1) * 1000)),
            'framework' => $fw,
            'jti' => self::jti($request->headers->get('DPoP')),
            'op_id' => $request->attributes->get('bench.op_id', 'NOT_FOUND'),
            'route_template' => $request->attributes->get('bench.route_template'),
            'raw_method' => $rawMethod,
            'effective_method' => $request->getMethod(),
            'raw_target' => $rawTarget,
            'path_params' => (object) $request->attributes->get('bench.path_params', []),
            'query' => $qi === false ? '' : substr($rawTarget, $qi + 1),
            'trust_headers' => (object) $trust,
            'denied' => (bool) $request->attributes->get('bench.denied', false),
            'status' => $status,
        ];
        $line = json_encode($rec, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)."\n";
        file_put_contents('php://stdout', $line);
        $file = getenv('LOG_FILE') ?: '/logs/executor.jsonl';
        $dir = dirname($file);
        if (is_dir($dir) || @mkdir($dir, 0777, true)) {
            @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
        }
        return $response;
    }
}
