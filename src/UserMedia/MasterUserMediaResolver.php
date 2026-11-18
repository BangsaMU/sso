<?php

namespace Bangsamu\Sso\UserMedia;

use Bangsamu\Master\Contracts\UserMediaResolver;

/**
 * Jembatan untuk paket bangsamu/master (api/getSignature, api/getParaf): nilai user_details berawalan "app03:" dibaca dari
 * cache lokal gambar Master Data. Hanya didaftarkan bila interface-nya ada (bangsamu/master versi yang mendukung).
 */
class MasterUserMediaResolver implements UserMediaResolver
{
    public function __construct(protected UserMediaCache $cache) {}

    public function localPath(string $type, string $email): ?string
    {
        return $this->cache->path($type, $email);
    }
}
