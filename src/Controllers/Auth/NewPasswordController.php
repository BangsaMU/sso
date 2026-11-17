<?php

namespace Bangsamu\Sso\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules;
use Illuminate\View\View;

// ADD THIS: Import the SSO Controller
use Bangsamu\Sso\Controllers\SsoController;
use Bangsamu\Sso\Support\SsoOutage;
use Illuminate\Http\Client\ConnectionException;

class NewPasswordController extends Controller
{
    /**
     * Display the password reset view.
     */
    public function create(Request $request): View
    {
        return view('sso::auth.reset-password', ['request' => $request]);
    }

    /**
     * Handle an incoming new password request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        $validated = $request->validateWithBag('updatePassword', [
            'token' => ['required'],
            'email' => ['required', 'email'],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);

        // If SSO is active, handle password reset through SSO first
        if (config('SsoConfig.main.ACTIVE')) {
            try {
                $sso = new SsoController();

                // Attempt to reset password via SSO
                $ssoResponse = $sso->reset($request);

                // server SSO menjawab error (bukan HTTP 200): dulu "SSO password reset failed" tanpa penjelasan
                if ($ssoResponse === false) {
                    $failureCount = SsoOutage::recordFailure('update_password', 'Server SSO menjawab HTTP '.($sso->lastHttpStatus ?? '?').' (bukan 200).');

                    return back()->withInput($request->only('email'))
                        ->withErrors(['email' => SsoOutage::message($failureCount)]);
                }

                SsoOutage::recordSuccess();
                $ssoResult = (object)$ssoResponse;

                // Check if SSO reset was successful
                if (!isset($ssoResult->status) || $ssoResult->status !== 'sukses') {
                    $errorMessage = $ssoResult->message ?? 'SSO password reset failed';
                    return back()->withInput($request->only('email'))
                        ->withErrors(['email' => $errorMessage]);
                }

                // If SSO reset was successful, also update local password for consistency
                $user = User::where('email', $validated['email'])->first();
                if ($user) {
                    $user->forceFill([
                        'password' => Hash::make($validated['password']),
                        'remember_token' => Str::random(60),
                    ])->save();

                    event(new PasswordReset($user));
                }

                return redirect()->route('login')->with('status', 'Password reset successful. You can now log in with your new password.');

            } catch (ConnectionException $e) {
                // server SSO tidak terjangkau (timeout / koneksi ditolak): pesan "coba lagi", lalu "maintenance"
                $failureCount = SsoOutage::recordFailure('update_password', $e->getMessage());

                return back()->withInput($request->only('email'))
                    ->withErrors(['email' => SsoOutage::message($failureCount)]);
            } catch (\Exception $e) {
                \Log::error('SSO password reset failed: ' . $e->getMessage(), [
                    'email' => $validated['email']
                ]);

                return back()->withInput($request->only('email'))
                    ->withErrors(['email' => 'Password reset failed. Please contact support or try again later.']);
            }
        }

        // Fallback to Laravel's default password reset for non-SSO mode
        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function (User $user) use ($request, $validated) {
                // Update local database password
                $user->forceFill([
                    'password' => Hash::make($validated['password']),
                    'remember_token' => Str::random(60),
                ])->save();

                event(new PasswordReset($user));
            }
        );

        // If the password was successfully reset, we will redirect the user back to
        // the application's home authenticated view. If there is an error we can
        // redirect them back to where they came from with their error message.
        return $status == Password::PASSWORD_RESET
                    ? redirect()->route('login')->with('status', __($status))
                    : back()->withInput($request->only('email'))
                        ->withErrors(['email' => __($status)]);
    }
}
