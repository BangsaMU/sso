<?php

/*
 * Stub class milik app (route bawaan paket ini memakai App\Http\Controllers\Controller dari app yang memasangnya).
 * Hanya dipakai saat menjalankan test paket.
 */

namespace App\Http\Controllers {
    if (! class_exists(Controller::class, false)) {
        abstract class Controller extends \Illuminate\Routing\Controller {}
    }
}
