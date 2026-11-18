<?php

namespace Bangsamu\Sso\UserMedia;

/**
 * Satu gambar lama di aplikasi (sumber sinkron): pemilik, jenis, file lokal, dan rujukan lokal (mis. nilai user_details).
 * $searched = path yang dicoba saat mencari file (laporan "File lokal hilang" dan peringatan salah setting folder).
 */
class LegacyUserMedia
{
    /**
     * @param  list<string>  $searched
     */
    public function __construct(
        public readonly string $email,
        public readonly string $type,
        public readonly ?string $path,
        public readonly ?string $localRef = null,
        public readonly mixed $userId = null,
        public readonly array $searched = [],
    ) {}
}
