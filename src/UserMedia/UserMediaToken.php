<?php

namespace Bangsamu\Sso\UserMedia;

use Illuminate\Support\Str;
use InvalidArgumentException;

/**
 * Token request ke API gambar user Master Data (K8). Format sama persis dengan verifier Master Data
 * (App\Services\UserMedia\UserMediaToken di repo master-data, docs/api-user-media.md):
 *
 *   umt1.<base64url(payload JSON)>.<base64url(tanda tangan Ed25519 atas "umt1.<payload>")>
 *
 * Klaim: v, iss (APP_CODE), aud=user-media, iat, exp (<= 60 detik), jti (sekali pakai), htm (method), htu (path tanpa
 * slash awal), bsh (sha256 hex isi: file untuk check, selain itu body mentah), sub (email pemilik), act (email pelaku), kid.
 */
class UserMediaToken
{
    public const PREFIX = 'umt1.';

    public const AUDIENCE = 'user-media';

    /**
     * Pasangan kunci baru (base64): secret untuk .env aplikasi, public untuk didaftarkan di Master Data.
     *
     * @return array{secret: string, public: string, fingerprint: string}
     */
    public static function generateKeyPair(): array
    {
        $pair = sodium_crypto_sign_keypair();
        $public = base64_encode(sodium_crypto_sign_publickey($pair));

        return [
            'secret' => base64_encode(sodium_crypto_sign_secretkey($pair)),
            'public' => $public,
            'fingerprint' => self::fingerprint($public),
        ];
    }

    public static function publicKeyFromSecret(string $secret): string
    {
        return base64_encode(sodium_crypto_sign_publickey_from_secretkey(self::decodeSecret($secret)));
    }

    /** 16 karakter awal sha256 kunci publik biner (sama dengan yang ditampilkan Master Data) */
    public static function fingerprint(string $publicKey): string
    {
        $raw = base64_decode(trim($publicKey), true);
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidArgumentException('Kunci publik tidak valid (harus base64 32 byte).');
        }

        return substr(hash('sha256', $raw), 0, 16);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public static function sign(string $secretKey, array $claims): string
    {
        $body = self::b64url(json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

        return self::PREFIX.$body.'.'.self::b64url(sodium_crypto_sign_detached(self::PREFIX.$body, self::decodeSecret($secretKey)));
    }

    /**
     * Klaim satu request. $path = path relatif root Master Data tanpa slash awal, mis. api/user-media/signature/check.
     *
     * @return array<string, mixed>
     */
    public static function claims(string $appCode, string $method, string $path, string $bodySha256, ?string $ownerEmail,
        ?string $actorEmail, int $ttl = 50, ?string $kid = null): array
    {
        $now = time();

        return array_filter([
            'v' => 1,
            'iss' => strtoupper($appCode),
            'aud' => self::AUDIENCE,
            'iat' => $now,
            'exp' => $now + max(1, min(60, $ttl)),
            'jti' => (string) Str::uuid(),
            'htm' => strtoupper($method),
            'htu' => trim($path, '/'),
            'bsh' => strtolower($bodySha256),
            'sub' => $ownerEmail !== null ? strtolower(trim($ownerEmail)) : null,
            'act' => $actorEmail !== null ? strtolower(trim($actorEmail)) : null,
            'kid' => $kid,
        ], fn ($value) => $value !== null);
    }

    public static function decodeSecret(string $secret): string
    {
        $raw = base64_decode(trim($secret), true);
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new InvalidArgumentException('MASTER_APP_PRIVATE_KEY tidak valid (harus base64 64 byte, buat dengan php artisan sso:app-key).');
        }

        return $raw;
    }

    public static function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
