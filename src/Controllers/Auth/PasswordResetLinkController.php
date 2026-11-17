<?php

namespace Bangsamu\Sso\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\View\View;

// ADD THIS: Import the missing trait and your SSO Controller
use Illuminate\Foundation\Auth\SendsPasswordResetEmails;
use Bangsamu\Sso\Controllers\SsoController;
use Bangsamu\Sso\Support\SsoOutage;
use Illuminate\Http\Client\ConnectionException;

class PasswordResetLinkController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Password Reset Link Controller
    |--------------------------------------------------------------------------
    |
    | This controller is responsible for handling password reset link requests
    | and uses a simple trait to include this behavior. You're free to
    | explore this trait and override any methods you wish to tweak.
    |
    */

    // ADD THIS: Use the trait to get the helper methods
    use SendsPasswordResetEmails;

    /**
     * Display the password reset link request view.
     */
    public function create(): View
    {
        // Use the view we created earlier
        return view('sso::auth.forgot-password');
    }

    /**
     * Handle an incoming password reset link request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        $request->validate(['email' => 'required|email']);

        // Check if SSO is active from your config
        if (config('SsoConfig.main.ACTIVE')) {
            // Your SSO logic
            $sso = new SsoController();

            // Server SSO tidak terjangkau / menjawab error: dulu timeout = halaman 500 dan error lain tampil
            // "Please wait before retrying". Kini pesan "coba lagi", setelah beberapa kali "maintenance" (SsoOutage).
            try {
                $attempt = $sso->forgot($request);
            } catch (ConnectionException $e) {
                return $this->ssoUnavailableResponse($request, 'forgot_password', $e->getMessage());
            }

            if ($attempt === false) {
                return $this->ssoUnavailableResponse($request, 'forgot_password', 'Server SSO menjawab HTTP '.($sso->lastHttpStatus ?? '?').' (bukan 200).');
            }

            $sso_cek = (object)$attempt;

            $response = '';
            switch (@$sso_cek->status) {
                case "sukses":
                    SsoOutage::recordSuccess();
                    $response = Password::RESET_LINK_SENT; // 'passwords.sent'
                    break;
                case "gagal":
                    // server SSO menangkap error kirim email (mis. SMTP) dan menjawab gagal + pesan error-nya; dulu
                    // tampil "email tidak ditemukan" padahal emailnya ada
                    if (self::isMailFailure($sso_cek->data ?? null)) {
                        return $this->ssoUnavailableResponse($request, 'forgot_password_mail', (string) $sso_cek->data, 'mail');
                    }
                    SsoOutage::recordSuccess();
                    $response = Password::INVALID_USER; // 'passwords.user'
                    break;
                default:
                    $response = Password::RESET_THROTTLED; // 'passwords.throttled'
            }

            // Now these methods will work because we added the trait
            return $response == Password::RESET_LINK_SENT
                        ? $this->sendResetLinkResponse($request, $response)
                        : $this->sendResetLinkFailedResponse($request, $response);

        } else {
            // This is the default Laravel non-SSO logic, it's correct
            $status = Password::sendResetLink($request->only('email'));

            return $status == Password::RESET_LINK_SENT
                        ? back()->with(['status' => __($status)])
                        : back()->withInput($request->only('email'))
                              ->withErrors(['email' => __($status)]);
        }
    }

    /**
     * Jawaban `gagal` server SSO berisi teks error selain "email tidak ditemukan" = SSO gagal mengirim email reset.
     * Data berupa daftar error validasi (array/objek) bukan kegagalan server.
     */
    protected static function isMailFailure(mixed $data): bool
    {
        return is_string($data) && $data !== '' && stripos($data, 'tidak ditemukan') === false && stripos($data, 'not found') === false;
    }

    /** Catat kegagalan server SSO dan kembali ke form dengan pesan "coba lagi" / "maintenance". */
    protected function ssoUnavailableResponse(Request $request, string $operation, string $error, string $kind = 'unavailable'): RedirectResponse
    {
        $failureCount = SsoOutage::recordFailure($operation, $error);

        return back()->withInput($request->only('email'))
            ->withErrors(['email' => SsoOutage::message($failureCount, $kind)]);
    }
}
