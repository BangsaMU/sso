<?php

namespace Bangsamu\Sso\UserMedia;

/**
 * Satu gambar lama di aplikasi (sumber sinkron): pemilik, jenis, file lokal, dan rujukan lokal (mis. nilai user_details).
 */
class LegacyUserMedia
{
    public function __construct(
        public readonly string $email,
        public readonly string $type,
        public readonly ?string $path,
        public readonly ?string $localRef = null,
        public readonly mixed $userId = null,
    ) {}
}
