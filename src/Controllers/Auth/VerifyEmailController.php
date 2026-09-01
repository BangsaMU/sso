<?php

namespace Bangsamu\Sso\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\RedirectResponse;

class VerifyEmailController extends Controller
{
    /**
     * Mark the authenticated user's email address as verified.
     */
    public function __invoke(EmailVerificationRequest $request): RedirectResponse
    {
        $LANDING_PAGE = config('SsoConfig.main.LANDING_PAGE','home');
        if ($request->user()->hasVerifiedEmail()) {
            return redirect()->intended(route($LANDING_PAGE, absolute: false).'?verified=1');
        }

        if ($request->user()->markEmailAsVerified()) {
            event(new Verified($request->user()));
        }

        return redirect()->intended(route($LANDING_PAGE, absolute: false).'?verified=1');
    }
}
