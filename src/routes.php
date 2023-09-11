<?php

Route::get('mud', function() {
    $value = config('SsoConfig');
    dd($value);
    echo 'Hello from the sso package!'.$value;
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
