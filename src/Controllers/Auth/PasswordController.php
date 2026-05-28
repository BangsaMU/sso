<?php

namespace Bangsamu\Sso\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;

class PasswordController extends Controller
{
    /**
     * Update the user's password.
     */
    public function update(Request $request): RedirectResponse
    {
        if (config('SsoConfig.main.ACTIVE')) {
            $validated = $request->validateWithBag('updatePassword', [
                'password' => ['required', Password::defaults(), 'confirmed'],
            ]);

            $ssoResult = $this->_updatePasswordViaSso($request);

            if ($ssoResult['respon']['success']) {
                $request->user()->update([
                    'password' => Hash::make($validated['password']),
                ]);
                return back()->with('status', 'password-updated');
            } else {
                return back()
                    ->with('status', 'password-update-failed') // A new status for the failure toast
                    ->with('error_message', $ssoResult['respon']['message'] ?? 'The SSO service failed to update the password.')
                    ->withInput(); // withInput() repopulates the form with the user's old input
            }
        } else {
            $validated = $request->validateWithBag('updatePassword', [
                'current_password' => ['required', 'current_password'],
                'password' => ['required', Password::defaults(), 'confirmed'],
            ]);

            $request->user()->update([
                'password' => Hash::make($validated['password']),
            ]);

            return back()->with('status', 'password-updated');
        }
    }

    /**
     * Force update the user's password (for weak default password change modal).
     * This uses stricter validation rules and returns JSON for AJAX.
     */
    public function forceUpdate(Request $request): JsonResponse
    {
        try {
            // Validate with strong password requirements
            $validated = $request->validate([
                'password' => [
                    'required',
                    'confirmed',
                    'min:8',
                    'regex:/[a-z]/',      // At least one lowercase letter
                    'regex:/[A-Z]/',      // At least one uppercase letter
                    'regex:/[0-9]/',      // At least one number
                    'not_in:Meindo12345', // Cannot be the weak default password
                ],
            ], [
                'password.min' => 'Password must be at least 8 characters.',
                'password.regex' => 'Password must contain uppercase, lowercase, and number.',
                'password.not_in' => 'You cannot use the default password. Please choose a strong password.',
                'password.confirmed' => 'Password confirmation does not match.',
            ]);

            // Update via SSO if active
            if (config('SsoConfig.main.ACTIVE')) {
                $ssoResult = $this->_updatePasswordViaSso($request);

                if (!$ssoResult['respon']['success']) {
                    return response()->json([
                        'success' => false,
                        'message' => $ssoResult['respon']['message'] ?? 'Failed to update password via SSO.',
                    ], 422);
                }
            }

            // Update local password
            $request->user()->update([
                'password' => Hash::make($validated['password']),
            ]);

            // Clear the password change required session flag
            session()->forget('password_change_required');

            // Clear is_forcechangepassword flag in master database
            if (config('SsoConfig.main.ACTIVE')) {
                try {
                    \Illuminate\Support\Facades\DB::connection('db_master')
                        ->table('master_user')
                        ->where('email', $request->user()->email)
                        ->update([
                            'is_forcechangepassword' => 0,
                            'updated_at' => now(),
                        ]);
                } catch (\Exception $e) {
                    \Log::warning('Failed to clear is_forcechangepassword in master DB', [
                        'email' => $request->user()->email,
                        'error' => $e->getMessage()
                    ]);
                }
            }

            return response()->json([
                'success' => true,
                'message' => 'Password updated successfully. You can now continue using the application.',
            ]);

        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed.',
                'errors' => $e->errors(),
            ], 422);
        }
    }

    /**
     * Handles the API call to the SSO service to update the password.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    private function _updatePasswordViaSso(Request $request): array
    {
        $password = $request->password;
        $token = $request->session()->get('auth.token'); // Assuming the token is stored here

        $data = ['password' => $password];
        if ($token) {
            $data['token'] = $token;
        }

        try {
            $ssoResponse = Http::timeout(config('SsoConfig.curl.TIMEOUT', 30))
                ->withOptions([
                    'verify' => config('SsoConfig.curl.VERIFY', false),
                ])
                ->post(config('SsoConfig.main.URL') . 'set_password', $data);

            $ssoBody = $ssoResponse->object();

            // Check for successful response from SSO
            if ($ssoResponse->successful() && isset($ssoBody->status) && $ssoBody->status == 'sukses') {
                return [
                    'respon' => [
                        'success' => true,
                        'message' => 'Password changed successfully via SSO.',
                    ],
                    'code' => 200,
                ];
            } else {
                // Handle failed response from SSO
                return [
                    'respon' => [
                        'success' => false,
                        'message' => $ssoBody->message ?? 'Password change failed at SSO service.',
                        'errors' => $ssoBody->data ?? null
                    ],
                    'code' => $ssoResponse->status(),
                ];
            }
        } catch (\Exception $e) {
            // Handle connection errors or other exceptions
            return [
                'respon' => [
                    'success' => false,
                    'message' => 'Could not connect to the authentication service.',
                    'errors' => $e->getMessage()
                ],
                'code' => 500,
            ];
        }
    }
}

