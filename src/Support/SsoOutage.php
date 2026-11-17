<?php

namespace Bangsamu\Sso\Support;

use Bangsamu\Sso\Events\SsoServerUnavailable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Hitungan gagal beruntun ke server SSO untuk Lupa Password dan Reset Password. Dulu server SSO yang timeout membuat
 * halaman Lupa Password error 500, jawaban error tampil "Please wait before retrying", dan SSO yang gagal mengirim email
 * tampil "We can't find a user with that email address".
 *
 * - Gagal (tidak terjangkau, bukan HTTP 200, gagal kirim email) = recordFailure(): hitungan naik, event
 *   SsoServerUnavailable dipicu, pesan ke user "coba lagi beberapa saat".
 * - Mulai `SsoConfig.outage.threshold` (bawaan 3) gagal beruntun dalam `SsoConfig.outage.window_minutes` (bawaan 15,
 *   jendela bergeser dari kegagalan terakhir) pesan berubah menjadi "maintenance".
 * - Jawaban normal server SSO (termasuk "email tidak ditemukan") = recordSuccess(): hitungan kosong.
 *
 * Pesan bisa diganti app lewat `SsoConfig.outage.messages.{unavailable,mail_failed,maintenance}`.
 */
class SsoOutage
{
    public const CACHE_KEY = 'bangsamu-sso:outage';

    public static function threshold(): int
    {
        return max(1, (int) config('SsoConfig.outage.threshold', 3));
    }

    public static function windowMinutes(): int
    {
        return max(1, (int) config('SsoConfig.outage.window_minutes', 15));
    }

    /**
     * Catat satu kegagalan dan picu event SsoServerUnavailable.
     *
     * @return int jumlah gagal beruntun termasuk yang ini
     */
    public static function recordFailure(string $operation, string $error): int
    {
        $now = time();
        $state = self::state();
        $state = [
            'count' => (int) ($state['count'] ?? 0) + 1,
            'first_failed_at' => (int) ($state['first_failed_at'] ?? $now),
            'last_failed_at' => $now,
            'operation' => $operation,
            'error' => mb_substr($error, 0, 1000),
        ];

        try {
            Cache::put(self::CACHE_KEY, $state, now()->addMinutes(self::windowMinutes()));
        } catch (Throwable) {
            // cache mati: hitungan tidak bertambah, pesan tetap "coba lagi"
        }

        Log::warning('SSO server bermasalah ('.$operation.', gagal ke-'.$state['count'].'): '.$state['error']);

        event(new SsoServerUnavailable(
            $operation,
            $state['error'],
            $state['count'],
            self::threshold(),
            (string) config('SsoConfig.main.URL', ''),
            $state['first_failed_at'],
        ));

        return $state['count'];
    }

    public static function recordSuccess(): void
    {
        try {
            Cache::forget(self::CACHE_KEY);
        } catch (Throwable) {
            //
        }
    }

    public static function failureCount(): int
    {
        return (int) (self::state()['count'] ?? 0);
    }

    /**
     * Pesan untuk user setelah gagal ke-$failureCount. $kind `mail` = server SSO hidup tetapi gagal mengirim email.
     */
    public static function message(int $failureCount, string $kind = 'unavailable'): string
    {
        if ($failureCount >= self::threshold()) {
            return (string) config('SsoConfig.outage.messages.maintenance',
                'Server login (SSO) sedang bermasalah atau dalam perbaikan (maintenance). Silakan coba lagi nanti, '
                .'atau hubungi admin bila berlanjut.');
        }

        return $kind === 'mail'
            ? (string) config('SsoConfig.outage.messages.mail_failed',
                'Email reset password gagal dikirim oleh server login (SSO). Coba lagi beberapa saat lagi.')
            : (string) config('SsoConfig.outage.messages.unavailable',
                'Server login (SSO) sedang tidak bisa dihubungi. Coba lagi beberapa saat lagi.');
    }

    /**
     * @return array<string, mixed>
     */
    private static function state(): array
    {
        try {
            return (array) Cache::get(self::CACHE_KEY, []);
        } catch (Throwable) {
            return [];
        }
    }
}
