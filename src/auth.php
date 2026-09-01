<?php

use Bangsamu\Sso\Controllers\Auth\AuthenticatedSessionController;
use Bangsamu\Sso\Controllers\Auth\ConfirmablePasswordController;
use Bangsamu\Sso\Controllers\Auth\EmailVerificationNotificationController;
use Bangsamu\Sso\Controllers\Auth\EmailVerificationPromptController;
use Bangsamu\Sso\Controllers\Auth\NewPasswordController;
use Bangsamu\Sso\Controllers\Auth\PasswordController;
use Bangsamu\Sso\Controllers\Auth\PasswordResetLinkController;
use Bangsamu\Sso\Controllers\Auth\RegisteredUserController;
use Bangsamu\Sso\Controllers\Auth\VerifyEmailController;

use Illuminate\Support\Facades\Route;


/*readme
  Solusi Arsitektur Terbaik:                                                                                                                               
  Jika autentikasi dan reset password ingin ditangani oleh package SSO:                                                                                    
                                                                                                                                                           
  1. Nonaktifkan reset password di Auth::routes() pada web.php:44:                                                                                         
    Auth::routes([
        'register' => !config('SsoConfig.main.ACTIVE'),
        'reset' => false,
        'confirm' => false,
    ]);
  
  2. Kembalikan nama route di auth.php ke nama standar Laravel (password.request, password.email, password.reset, password.confirm, password.update).      
  Dengan begitu, seluruh view blade, notifikasi email, dan middleware bawaan Laravel tetap bekerja normal tanpa bentrok saat optimize.
  
*/

Route::middleware('web')->group(function () {
    // Route::get('register', [RegisteredUserController::class, 'create'])
    //     ->name('register');

    // Route::post('register', [RegisteredUserController::class, 'store']);

    Route::get('login', [AuthenticatedSessionController::class, 'create'])
        ->name('login');

    Route::post('login', [AuthenticatedSessionController::class, 'store']);

    Route::get('forgot-password', [PasswordResetLinkController::class, 'create'])
        ->name('password.forgot');

    Route::post('forgot-password', [PasswordResetLinkController::class, 'store'])
        ->name('password.reset');

    Route::get('reset-password/{token}', [NewPasswordController::class, 'create'])
        ->name('reset.password');

    Route::get('password/reset/{token}', [NewPasswordController::class, 'create'])
        ->name('password.reset:token');

    Route::post('reset-password', [NewPasswordController::class, 'store'])
        ->name('password.store');
});

Route::middleware(['web', 'auth'])->group(function () {
    Route::get('verify-email', EmailVerificationPromptController::class)
        ->name('verification.notice');

    Route::get('verify-email/{id}/{hash}', VerifyEmailController::class)
        ->middleware(['signed', 'throttle:6,1'])
        ->name('verification.verify');

    Route::post('email/verification-notification', [EmailVerificationNotificationController::class, 'store'])
        ->middleware('throttle:6,1')
        ->name('verification.send');

    Route::get('confirm-password', [ConfirmablePasswordController::class, 'show'])
        ->name('password-confirm');

    Route::post('confirm-password', [ConfirmablePasswordController::class, 'store'])
        ->name('password-confirm-store'); 

    Route::put('password', [PasswordController::class, 'update'])->name('password-update');

    Route::post('password/force-update', [PasswordController::class, 'forceUpdate'])->name('password.force-update');

    Route::post('logout', [AuthenticatedSessionController::class, 'destroy'])
        ->name('logout');

    Route::get('dashboard', function () {
        return view('sso::mud');
    })->name('dashboard');
});
