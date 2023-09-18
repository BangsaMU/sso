<?php

use Illuminate\Support\Facades\Route;

Route::get('mud', function() {
    $value = config('SsoConfig.main.APP_CODE');
    echo 'Hello from the sso package!'.json_encode($value);
});

Route::get('mud-view', function () {
    return view('sso::mud');
});

Route::get('getIp', function () {
    return view('sso::mud');
});


Route::get('get-ip',  [Bangsamu\Sso\SsoControllerOld::class, 'getIp'])
->name('get-ip');

Route::get('get-ip2',  [Bangsamu\Sso\Controllers\SsoController::class, 'getIp'])
->name('get-ip2');


Route::get('/session-cek', [Bangsamu\Sso\Controllers\SsoController::class, 'sessionCek'])
    ->name('session-cek');

Route::get('/session-set/{token}', [\Bangsamu\Sso\Controllers\SsoController::class, 'sessionSet'])
    ->name('session-set');
// Route::get('/session-set/{token}', [Bangsamu\Sso\Controllers\SsoController::class, 'sessionSet'])
//     ->name('session-set');
Route::get('/session-unset/{token}', [Bangsamu\Sso\Controllers\SsoController::class, 'sessionUnset'])
    ->name('session-unset');
Route::get('/session-test/{credentials?}', [Bangsamu\Sso\Controllers\SsoController::class, 'auth'])
    ->name('session-test');
