<?php

namespace Bangsamu\Sso\UserMedia\Events;

use Bangsamu\Sso\UserMedia\LegacyUserMedia;

/**
 * Dikirim `sso:user-media-sync` setelah markSynced(): gambar lama sama dengan Master Data (atau baru diisi dari file ini).
 * Aplikasi bisa mendengarkan event ini untuk pekerjaan tambahan (Activity Log, cache status) tanpa membuat sumber sendiri.
 */
class LegacyUserMediaSynced
{
    /**
     * @param  array<string, mixed>  $media  status gambar di Master Data (sha256, pixel_hash, uploaded_at, source_app)
     */
    public function __construct(
        public readonly LegacyUserMedia $item,
        public readonly array $media,
    ) {}
}
