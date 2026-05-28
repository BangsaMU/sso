<?php

namespace Bangsamu\Sso\Services;

use App\Models\User;
use Bangsamu\Sso\Controllers\SsoController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class SsoAuthService
{
    /**
     * Authenticates a user via the SSO provider, finds or creates a local user,
     * and logs them in.
     *
     * @param Request $request
     * @return void
     * @throws ValidationException
     */
    public function authenticate(Request $request): void
    {
        $sso = new SsoController();
        $ssoResponse = $sso->auth($request);

        if (!$ssoResponse || empty($ssoResponse['data'])) {
            $this->throwFailedLoginException();
        }

        $ssoUser = (object) $ssoResponse['data'];

        if (empty($ssoUser->id) || !$ssoUser->is_active) {
            $this->throwFailedLoginException('Your SSO account is inactive or invalid.');
        }

        // Find or create the local user corresponding to the SSO user
        $localUser = $this->findOrCreateUser($ssoUser, $request, $sso);

        // If user creation failed for some reason
        if (!$localUser) {
            $this->throwFailedLoginException('Your account could not be registered locally, please contact the administrator.');
        }

        // Log the user into the application
        Auth::login($localUser, $request->boolean('remember'));

        // Store the SSO token in the session if needed
        if ($request->hasSession()) {
            $request->session()->put('auth.token', $ssoUser->token);
        }
    }

    /**
     * Finds an existing user by email or creates a new one if not found.
     *
     * @param object $ssoUser
     * @param Request $request
     * @param SsoController $sso
     * @return User|null
     */
    private function findOrCreateUser(object $ssoUser, Request $request, SsoController $sso): ?User
    {
        // Attempt to find the user by their email in the local database
        $user = User::where('email', $ssoUser->email)->first();

        if ($user) {
            return $user; // User found, return it.
        }

        // If user does not exist, create them locally.
        $data = [
            'name' => $ssoUser->name,
            'email' => $ssoUser->email,
            'is_active' => 1,
            // You may want a more secure default password or use a UUID
            'password' => Hash::make($request->password ?? \Str::random(16)),
        ];

        // The old code called a method on the sso controller to create a user.
        // It's better to handle user creation within your own app if possible,
        // but for compatibility, we will call it here.
        // A better approach would be: return User::create($data);
        return $sso->create($data);
    }

    /**
     * Throws a standard failed login validation exception.
     *
     * @param string $message
     * @return void
     * @throws ValidationException
     */
    private function throwFailedLoginException(string $message = 'These credentials do not match our records.'): void
    {
        throw ValidationException::withMessages([
            'email' => [trans($message)],
        ]);
    }
}
