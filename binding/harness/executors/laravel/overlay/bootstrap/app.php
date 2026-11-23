<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(using: function () {
        // No 'web' group (no sessions/CSRF) and no automatic 'api' prefix: routes/bench.php
        // declares the full /api/v1 and /api/v2 route groups itself.
        Route::group([], base_path('routes/bench.php'));
    })
    ->withMiddleware(function (Middleware $middleware): void {
        // Outermost global middleware: raw capture + JSONL log + NOT_FOUND mapping.
        $middleware->prepend(\App\Http\Middleware\BenchLog::class);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->dontReport([\Throwable::class]);
    })
    ->create();
