<?php

use Illuminate\Foundation\Application;
use Illuminate\Http\Request;

define('LARAVEL_START', microtime(true));

if (file_exists($maintenance = __DIR__.'/../storage/framework/maintenance.php')) {
    require $maintenance;
}

require __DIR__.'/../vendor/autoload.php';

/** @var Application $app */
$app = require_once __DIR__.'/../bootstrap/app.php';

// Method override (Laravel "method spoofing") is ON by default in Laravel: Illuminate\Http\Request::capture()
// and Illuminate\Foundation\Http\Kernel::handle() both call enableHttpMethodParameterOverride() (`_method`,
// read from the body and then the query), and Symfony's Request::getMethod() honours the
// X-HTTP-Method-Override header on POST unconditionally. Neither has a Laravel config switch.
// OVERRIDE=off uses Symfony's own API for this (http-foundation >= 7.4):
// Request::setAllowedHttpMethodOverride([]) makes getMethod() return the real method for every
// request. OVERRIDE=on leaves the stock Laravel behaviour untouched.
if ((getenv('OVERRIDE') ?: 'off') !== 'on') {
    Request::setAllowedHttpMethodOverride([]);
}

$request = Request::capture();

$app->handleRequest($request);
