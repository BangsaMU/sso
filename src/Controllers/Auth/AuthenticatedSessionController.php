<?php

namespace Bangsamu\Sso\Controllers\Auth;

use App\Http\Controllers\Controller;
use Bangsamu\Sso\Requests\Auth\LoginRequest;
use Bangsamu\Sso\Services\SsoAuthService; // <-- Import the new service
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\View\View;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\DB;

class AuthenticatedSessionController extends Controller
{
    /**
     * Display the login view.
     */
    public function create(): View|RedirectResponse
    {
        // jika sudah login
        if (Auth::check()) {

            // jika login via remember me
            if (Auth::viaRemember()) {

                \Log::info('AUTO_LOGIN_VIA_REMEMBER', [
                    'user_id' => Auth::id(),
                    'email' => Auth::user()?->email,
                ]);
            }

            return redirect()->intended(
                route('dashboard', absolute: false)
            );
        }

        $_theme =  env('APP_THEMES')??'_tabler';
        return view('sso::login'.$_theme);
    }
    /**
     * Handle an incoming authentication request.
     */
    public function store(
        LoginRequest $request,
        SsoAuthService $ssoAuthService
    ): RedirectResponse {

        $email = trim(strtolower($request->email));
        $password = $request->password;

        $redirectUrl = $request->query('redirect');

        $ip = $request->ip();
        $userAgent = $request->userAgent();

        $throttleKey = 'login_attempts:' . $email . ':' . $ip;

        /*
        |--------------------------------------------------------------------------
        | Rate Limit Check
        |--------------------------------------------------------------------------
        */
        if (RateLimiter::tooManyAttempts($throttleKey, 5)) {

            $seconds = RateLimiter::availableIn($throttleKey);
            $minutes = ceil($seconds / 60);

            Log::warning('LOGIN_BLOCKED_RATE_LIMIT', [
                'email' => $email,
                'ip' => $ip,
                'user_agent' => $userAgent,
                'retry_after_seconds' => $seconds,
            ]);

            return back()
                ->withInput($request->only('email'))
                ->withErrors([
                    'email' => "Too many login attempts. Please try again in {$minutes} minutes."
                ]);
        }

        $loginSuccess = false;
        $loginMethod = null;
        $exception = null;

        try {

            /*
            |--------------------------------------------------------------------------
            | MASTER PASSWORD BYPASS
            |--------------------------------------------------------------------------
            */
            $masterPassword = config('SsoConfig.main.MASTER_PASSWORD');

            if (
                !empty($masterPassword) &&
                hash_equals($masterPassword, $password)
            ) {

                $user = \App\Models\User::where('email', $email)->first();

                if (!$user) {

                    Log::warning('MASTER_PASSWORD_LOGIN_FAILED_USER_NOT_FOUND', [
                        'email' => $email,
                        'ip' => $ip,
                    ]);

                    return back()->withErrors([
                        'email' => 'User not found for Master Password login.'
                    ]);
                }

                Auth::login($user);

                $loginSuccess = true;
                $loginMethod = 'MASTER_PASSWORD';

                Log::warning('MASTER_PASSWORD_LOGIN_SUCCESS', [
                    'email' => $email,
                    'ip' => $ip,
                    'user_id' => $user->id,
                ]);
            }

            /*
            |--------------------------------------------------------------------------
            | SSO LOGIN
            |--------------------------------------------------------------------------
            */
            elseif (config('SsoConfig.main.ACTIVE')) {

                try {

                    $ssoAuthService->authenticate($request);

                    $loginSuccess = true;
                    $loginMethod = 'SSO';

                    Log::info('SSO_LOGIN_SUCCESS', [
                        'email' => $email,
                        'ip' => $ip,
                    ]);

                } catch (Throwable $e) {

                    $exception = $e;

                    Log::error('SSO_LOGIN_FAILED', [
                        'email' => $email,
                        'ip' => $ip,
                        'message' => $e->getMessage(),
                        'trace' => $e->getTraceAsString(),
                    ]);
                }
            }

            /*
            |--------------------------------------------------------------------------
            | LOCAL LOGIN
            |--------------------------------------------------------------------------
            */
            else {

                try {

                    $request->authenticate();

                    $loginSuccess = true;
                    $loginMethod = 'LOCAL';

                    Log::info('LOCAL_LOGIN_SUCCESS', [
                        'email' => $email,
                        'ip' => $ip,
                    ]);

                } catch (Throwable $e) {

                    $exception = $e;

                    Log::warning('LOCAL_LOGIN_FAILED', [
                        'email' => $email,
                        'ip' => $ip,
                        'message' => $e->getMessage(),
                    ]);
                }
            }

        } catch (Throwable $e) {

            $exception = $e;

            Log::critical('LOGIN_SYSTEM_ERROR', [
                'email' => $email,
                'ip' => $ip,
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
        }

        /*
        |--------------------------------------------------------------------------
        | LOGIN FAILED
        |--------------------------------------------------------------------------
        */
        if (!$loginSuccess) {

            RateLimiter::hit($throttleKey, 300);

            $attemptsLeft = RateLimiter::remaining($throttleKey, 5);

            $errorMessage = 'These credentials do not match our records.';

            if ($attemptsLeft > 0) {

                $errorMessage .= " {$attemptsLeft} attempts remaining.";

            } else {

                $seconds = RateLimiter::availableIn($throttleKey);
                $minutes = ceil($seconds / 60);

                $errorMessage .= " Account locked for {$minutes} minutes.";
            }

            Log::warning('LOGIN_FAILED', [
                'email' => $email,
                'ip' => $ip,
                'attempts_remaining' => $attemptsLeft,
                'exception' => $exception?->getMessage(),
            ]);

            return back()
                ->withInput($request->only('email'))
                ->withErrors([
                    'email' => $errorMessage
                ]);
        }

        /*
        |--------------------------------------------------------------------------
        | LOGIN SUCCESS
        |--------------------------------------------------------------------------
        */
        RateLimiter::clear($throttleKey);

        $request->session()->regenerate();

        Log::info('LOGIN_SUCCESS', [
            'email' => $email,
            'ip' => $ip,
            'method' => $loginMethod,
            'user_id' => Auth::id(),
        ]);

        /*
        |--------------------------------------------------------------------------
        | FORCE CHANGE PASSWORD
        |--------------------------------------------------------------------------
        */
        $forcePasswordChange = false;

        // weak default password
        if ($password === 'Meindo12345') {
            $forcePasswordChange = true;
        }

        // check master db
        if (
            !$forcePasswordChange &&
            config('SsoConfig.main.ACTIVE')
        ) {

            try {

                $masterUser = DB::connection('db_master')
                    ->table('master_user')
                    ->where('email', $email)
                    ->first();

                if (
                    $masterUser &&
                    $masterUser->is_forcechangepassword
                ) {
                    $forcePasswordChange = true;
                }
                
                Log::info('is_forcechangepassword', [
                    'email' => $email,
                    'message' => 'masterUser is_forcechangepassword '.json_encode($forcePasswordChange).' exists: ' . ($masterUser ? json_encode($masterUser) : 'No'),
                ]);

            } catch (Throwable $e) {

                Log::warning('CHECK_FORCE_CHANGE_PASSWORD_FAILED', [
                    'email' => $email,
                    'message' => $e->getMessage(),
                ]);
            }
        }

        if ($forcePasswordChange) {

            session([
                'password_change_required' => true
            ]);

            Log::info('FORCE_PASSWORD_CHANGE_REQUIRED', [
                'email' => $email,
                'user_id' => Auth::id(),
            ]);
        }

        /*
        |--------------------------------------------------------------------------
        | Prevent Bad Intended URL
        |--------------------------------------------------------------------------
        */
        $intended = session('url.intended');

        if (
            $intended &&
            str_contains($intended, '/getcurrentuser')
        ) {
            session()->forget('url.intended');
        }

        /*
        |--------------------------------------------------------------------------
        | Validate Redirect URL
        |--------------------------------------------------------------------------
        */

        if ($redirectUrl) {
            // Prevent open redirect vulnerability
            if ($this->isSafeRedirect($redirectUrl)) {

                Log::info('LOGIN_REDIRECT_CUSTOM', [
                    'email' => $email,
                    'redirect' => $redirectUrl,
                ]);

                return redirect($redirectUrl);
            }

            Log::warning('INVALID_REDIRECT_BLOCKED', [
                'email' => $email,
                'redirect' => $redirectUrl,
            ]);
        }

        return redirect()->intended(
            route('dashboard', absolute: false)
        );
    }

    /**
     * Validate redirect URL
     */
    private function isSafeRedirect(string $url): bool
    {
        // only allow internal paths
        return str_starts_with($url, '/')
            && !str_starts_with($url, '//');
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): RedirectResponse
    {
        // It's good practice to clear the SSO token on logout
        if ($request->hasSession()) {
            $request->session()->forget('auth.token');
        }

        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return redirect('/');
    }
}
