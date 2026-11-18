<?php

namespace Bangsamu\Sso\UserMedia\Contracts;

use Bangsamu\Sso\UserMedia\LegacyUserMedia;

/**
 * Sumber gambar lama di aplikasi (disediakan aplikasi, didaftarkan di config sso_user_media.legacy_source), dipakai
 * `php artisan sso:user-media-sync` untuk memindahkan gambar lokal ke Master Data dengan aturan rancangan.
 */
interface LegacyUserMediaSource
{
    /**
     * Gambar lama per user per jenis. path = file lokal absolut (null / tidak ada = "file hilang" di laporan).
     *
     * @return iterable<LegacyUserMedia>
     */
    public function items(?string $type = null, ?string $email = null): iterable;

    /**
     * Gambar sudah ada di Master Data dan sama (atau baru diisi dari file ini): aplikasi boleh beralih memakai gambar
     * Master Data, mis. user_details diganti rujukan "app03:<type>". File lokal JANGAN dihapus (Tahap 6).
     *
     * @param  array<string, mixed>  $media  status gambar di Master Data (sha256, pixel_hash, uploaded_at, source_app)
     */
    public function markSynced(LegacyUserMedia $item, array $media): void;
}
