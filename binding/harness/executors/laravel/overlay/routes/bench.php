<?php

use App\Http\Controllers\BenchController as B;
use Illuminate\Support\Facades\Route;

Route::prefix('api/v1')->group(function () {
    Route::get('accounts', [B::class, 'listAccounts']);
    Route::get('accounts/{id}', [B::class, 'getAccount']);
    Route::put('accounts/{id}', [B::class, 'updateAccount']);
    Route::delete('accounts/{id}', [B::class, 'deleteAccount']);
    Route::post('accounts/{id}/actions', [B::class, 'accountAction']);
    Route::post('transfers', [B::class, 'createTransfer']);
    Route::post('graphql', [B::class, 'graphql']);
    Route::get('me', [B::class, 'me']);
    Route::get('admin/users', [B::class, 'adminListUsers']);
    Route::delete('admin/users/{id}', [B::class, 'adminDeleteUser']);
    Route::get('health', [B::class, 'health']);
    Route::get('public/{file}', [B::class, 'publicFile']);

    // ROUTES=v2 (default off) adds the richer v1 route space (W15 ext-routes). Off => :latest.
    if (getenv('ROUTES') === 'v2') {
        Route::post('accounts/{id}', [B::class, 'postAccount']);                     // POST shares the GET/PUT/DELETE path
        Route::get('accounts/{id}/statements', [B::class, 'getStatements']);         // nested same-method route
        Route::delete('accounts/{id}/statements/{sid}', [B::class, 'deleteStatement']);
        Route::get('files/{path}', [B::class, 'catchAllFile'])->where('path', '.*'); // catch-all
    }
});

// /api/v2 as a route group with a prefix (Laravel's mechanism for mounting a group of routes).
Route::prefix('api/v2')->group(function () {
    Route::get('accounts/{id}', [B::class, 'getAccountV2']);
});
