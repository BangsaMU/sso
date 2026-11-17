<?php

namespace Bangsamu\Sso\Events;

/**
 * Server SSO bermasalah saat Lupa Password / Reset Password: tidak terjangkau (timeout, koneksi ditolak), menjawab
 * error (bukan HTTP 200), atau gagal mengirim email reset. Dipicu setiap kegagalan oleh SsoOutage::recordFailure();
 * app pemakai paket boleh mendengarkannya, mis. untuk mengirim email ke admin begitu $reachedThreshold.
 */
class SsoServerUnavailable
{
    /**
     * @param  string  $operation  forgot_password | forgot_password_mail | update_password
     * @param  string  $error  pesan error terakhir (cURL, status HTTP, atau pesan server SSO)
     * @param  int  $failureCount  jumlah gagal beruntun dalam jendela SsoOutage::windowMinutes()
     * @param  int  $threshold  batas gagal beruntun sebelum pesan ke user berubah menjadi "maintenance"
     * @param  string  $serverUrl  SsoConfig.main.URL
     * @param  int  $firstFailedAt  unix time kegagalan pertama dalam rangkaian ini
     */
    public function __construct(
        public readonly string $operation,
        public readonly string $error,
        public readonly int $failureCount,
        public readonly int $threshold,
        public readonly string $serverUrl,
        public readonly int $firstFailedAt,
    ) {}

    public function reachedThreshold(): bool
    {
        return $this->failureCount >= $this->threshold;
    }
}
