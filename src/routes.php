<?php

Route::get('mud', function() {
    $value = config('SsoConfig');
    dd($value);
    echo 'Hello from the sso package!'.$value;
});

Route::get('mud-view', function () {
    return view('sso::mud');
});
