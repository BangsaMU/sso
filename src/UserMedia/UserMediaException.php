<?php

namespace Bangsamu\Sso\UserMedia;

use RuntimeException;

/**
 * Gagal memanggil API gambar user Master Data. $reason = kode tetap dari Master Data (data.reason, mis.
 * replace_requires_confirmation, invalid_token, storage_unavailable) atau dari client: not_configured, unreachable,
 * dev_to_production_blocked, unhealthy. $data = isi data jawaban (mis. data.master pada 409).
 */
class UserMediaException extends RuntimeException
{
    /**
     * @param  array<string, mixed>  $data
     */
    public function __construct(string $message, public readonly string $reason = 'error', public readonly int $status = 0,
        public readonly array $data = [])
    {
        parent::__construct($message);
    }

    /** Master Data / penyimpanan tidak bisa dipakai sekarang (upload dikunci, PDF tanpa cache ditunda: K3) */
    public function isUnavailable(): bool
    {
        return in_array($this->reason, ['unreachable', 'storage_unavailable', 'unhealthy', 'not_configured'], true)
            || $this->status >= 500;
    }
}
