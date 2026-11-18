<?php

namespace Bangsamu\Sso\UserMedia;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Throwable;

/**
 * Client API gambar user Master Data (signature, paraf, foto profil; K1, K8, K10). Master Data satu-satunya penulis bucket;
 * aplikasi ini memanggil api/user-media/* dengan token Ed25519 (UserMediaToken). Kontrak: master-data docs/api-user-media.md.
 *
 * Upload: check() (normalisasi + banding di Master Data) → bila master_exists=false langsung commit(); bila same=true
 * tidak perlu apa-apa; bila requires_confirmation=true tampilkan modal berdampingan, lalu commit(..., true).
 * Semua penulisan didahului assertWritable(): health OK dan bukan dev yang menulis ke Master Data produksi.
 */
class UserMediaClient
{
    public const TYPES = ['signature', 'paraf', 'profile_photo'];

    public function configured(): bool
    {
        return filled($this->baseUrl()) && filled(config('sso_user_media.private_key')) && $this->appCode() !== '';
    }

    public function appCode(): string
    {
        return strtoupper(trim((string) (config('sso_user_media.app_code') ?: config('SsoConfig.main.APP_CODE'))));
    }

    public function baseUrl(): string
    {
        return rtrim((string) config('sso_user_media.url'), '/');
    }

    /**
     * Master Data hidup dan bucket bisa dibaca/ditulis. Di-cache health_cache_seconds (gagal pun di-cache).
     *
     * @return array{ok: bool, reachable: bool, bucket: ?string, env: ?string, app_code: ?string, checked_at: ?string, errors: list<string>}
     */
    public function health(bool $fresh = false): array
    {
        $cacheKey = 'sso_user_media_health:'.md5($this->baseUrl().'|'.$this->appCode());
        if (! $fresh && is_array($cached = Cache::get($cacheKey))) {
            return $cached;
        }

        $result = ['ok' => false, 'reachable' => false, 'bucket' => null, 'env' => null, 'app_code' => null, 'checked_at' => now()->toIso8601String(), 'errors' => []];
        if (! $this->configured()) {
            $result['errors'][] = 'Client gambar Master Data belum dikonfigurasi (USER_MEDIA_URL, MASTER_APP_PRIVATE_KEY, APP_CODE).';
        } else {
            try {
                $response = $this->send('GET', 'api/user-media/health');
                $data = (array) ($response->json('data') ?? []);
                $result = array_merge($result, array_intersect_key($data, array_flip(['bucket', 'env', 'app_code', 'checked_at'])), [
                    'ok' => $response->successful() && ($data['ok'] ?? false) === true,
                    'reachable' => true,
                    'errors' => array_values((array) ($data['errors'] ?? (isset($data['message']) ? [$data['message']] : []))),
                ]);
                if (! $result['ok'] && $result['errors'] === []) {
                    $result['errors'][] = 'Master Data menjawab HTTP '.$response->status().'.';
                }
            } catch (UserMediaException $e) {
                $result['errors'][] = $e->getMessage();
            }
        }

        Cache::put($cacheKey, $result, (int) config('sso_user_media.health_cache_seconds', 60));
        if (! $result['ok']) {
            Log::warning('[UserMediaClient] health gagal: '.implode(' | ', $result['errors']));
        }

        return $result;
    }

    /** sebelum upload/hapus: health OK dan bukan aplikasi dev yang menulis ke Master Data produksi */
    public function assertWritable(): void
    {
        if (! $this->configured()) {
            throw new UserMediaException('Client gambar Master Data belum dikonfigurasi.', 'not_configured');
        }
        $health = $this->health();
        if (! $health['ok']) {
            throw new UserMediaException('Server Master Data / penyimpanan gambar tidak dapat dihubungi. '.implode(' ', $health['errors']), 'unhealthy', 503,
                ['health' => $health]);
        }
        if (config('sso_user_media.block_dev_to_production', true) && ! app()->environment('production') && ($health['env'] ?? null) === 'production') {
            throw new UserMediaException('APP_ENV aplikasi ini '.app()->environment().' tetapi Master Data yang dituju production (bucket '
                .($health['bucket'] ?? '?').'). Arahkan USER_MEDIA_URL ke Master Data dev.', 'dev_to_production_blocked', 0, ['health' => $health]);
        }
    }

    /**
     * Status ketiga jenis: [type => {exists, sha256, pixel_hash, width, height, bytes, source_app, uploaded_by_email, uploaded_at}].
     *
     * @return array<string, array<string, mixed>>
     */
    public function status(string $email): array
    {
        $email = $this->email($email);

        return (array) ($this->data($this->send('GET', 'api/user-media/status', $email, null, ['email' => $email]))['media'] ?? []);
    }

    /**
     * Isi PNG. $etag = sha256 yang sudah dimiliki cache (If-None-Match).
     *
     * @return array{status: int, body: ?string, sha256: ?string, pixel_hash: ?string, uploaded_at: ?string, source_app: ?string}
     */
    public function download(string $type, string $email, ?string $etag = null): array
    {
        $this->assertType($type);
        $email = $this->email($email);
        $response = $this->send('GET', 'api/user-media/'.$type, $email, null, ['email' => $email], null, null, null,
            $etag ? ['If-None-Match' => '"'.$etag.'"'] : []);

        if ($response->status() === 304 || $response->status() === 404) {
            return ['status' => $response->status(), 'body' => null, 'sha256' => $response->status() === 304 ? $etag : null,
                'pixel_hash' => $response->header('X-Pixel-Hash') ?: null, 'uploaded_at' => null, 'source_app' => null];
        }
        if (! $response->successful()) {
            $this->data($response); // melempar UserMediaException
        }

        $body = $response->body();

        return [
            'status' => 200,
            'body' => $body,
            'sha256' => trim((string) $response->header('ETag'), '"W/') ?: hash('sha256', $body),
            'pixel_hash' => $response->header('X-Pixel-Hash') ?: null,
            'uploaded_at' => $response->header('X-Uploaded-At') ?: null,
            'source_app' => $response->header('X-Source-App') ?: null,
        ];
    }

    /**
     * Kandidat upload: dinormalisasi dan dibandingkan di Master Data.
     *
     * @return array<string, mixed> data (master_exists, same, requires_confirmation, candidate, master, check_token)
     */
    public function check(string $type, string $ownerEmail, string $actorEmail, string $bytes, string $filename = 'image.png'): array
    {
        $this->assertType($type);
        $this->assertWritable();
        $owner = $this->email($ownerEmail);

        return $this->data($this->send('POST', 'api/user-media/'.$type.'/check', $owner, $actorEmail, [], null,
            ['contents' => $bytes, 'filename' => $filename], (float) config('sso_user_media.upload_timeout', 20)));
    }

    /**
     * Simpan kandidat check_token. confirm_replace wajib true bila gambar Master Data ada dan berbeda (409 tanpa itu).
     *
     * @return array<string, mixed> data (result: created|replaced|same, media)
     */
    public function commit(string $type, string $ownerEmail, string $actorEmail, string $checkToken, bool $confirmReplace = false): array
    {
        $this->assertType($type);
        $this->assertWritable();
        $owner = $this->email($ownerEmail);
        $body = json_encode(['email' => $owner, 'check_token' => $checkToken, 'confirm_replace' => $confirmReplace], JSON_THROW_ON_ERROR);

        return $this->data($this->send('POST', 'api/user-media/'.$type.'/commit', $owner, $actorEmail, [], $body, null,
            (float) config('sso_user_media.upload_timeout', 20)));
    }

    /**
     * Hapus di Master Data untuk semua aplikasi (K7). Panggil hanya setelah user menyetujui peringatan.
     *
     * @return array<string, mixed>
     */
    public function delete(string $type, string $ownerEmail, string $actorEmail): array
    {
        $this->assertType($type);
        $this->assertWritable();
        $owner = $this->email($ownerEmail);

        return $this->data($this->send('DELETE', 'api/user-media/'.$type, $owner, $actorEmail, ['email' => $owner, 'confirm_delete' => 'true']));
    }

    /**
     * @param  array<string, scalar>  $query
     * @param  array{contents: string, filename: string}|null  $file
     * @param  array<string, string>  $headers
     */
    protected function send(string $method, string $path, ?string $owner = null, ?string $actor = null, array $query = [], ?string $jsonBody = null,
        ?array $file = null, ?float $timeout = null, array $headers = []): Response
    {
        if (! $this->configured()) {
            throw new UserMediaException('Client gambar Master Data belum dikonfigurasi.', 'not_configured');
        }
        $secret = (string) config('sso_user_media.private_key');
        $bodySha256 = hash('sha256', $file['contents'] ?? $jsonBody ?? '');
        try {
            $kid = UserMediaToken::fingerprint(UserMediaToken::publicKeyFromSecret($secret));
            $token = UserMediaToken::sign($secret, UserMediaToken::claims($this->appCode(), $method, $path, $bodySha256, $owner, $actor,
                (int) config('sso_user_media.token_ttl', 50), $kid));
        } catch (InvalidArgumentException $e) {
            // kunci terisi tetapi rusak (bukan base64 64 byte): sama dengan belum dikonfigurasi (health tidak ok, upload
            // dikunci, PDF tanpa cache ditunda), bukan exception yang lolos dan membuat halaman app error 500
            throw new UserMediaException($e->getMessage(), 'not_configured');
        }

        $url = $this->baseUrl().'/'.$path.($query !== [] ? '?'.http_build_query($query) : '');
        $request = $this->request($token, $timeout, $headers);

        try {
            if ($file !== null) {
                return $request->attach('file', $file['contents'], $file['filename'])->post($url, ['email' => $owner]);
            }
            if ($jsonBody !== null) {
                return $request->withBody($jsonBody, 'application/json')->send($method, $url);
            }

            return $request->send($method, $url);
        } catch (ConnectionException $e) {
            throw new UserMediaException('Master Data tidak dapat dihubungi: '.$e->getMessage(), 'unreachable');
        } catch (Throwable $e) {
            if ($e instanceof UserMediaException) {
                throw $e;
            }
            throw new UserMediaException('Permintaan ke Master Data gagal: '.$e->getMessage(), 'unreachable');
        }
    }

    /** @param  array<string, string>  $headers */
    protected function request(string $token, ?float $timeout, array $headers): PendingRequest
    {
        return Http::withToken($token)
            ->acceptJson()
            ->withHeaders($headers)
            ->withOptions([
                'timeout' => $timeout ?? (float) config('sso_user_media.timeout', 3),
                'connect_timeout' => (float) config('sso_user_media.connect_timeout', 2),
                'verify' => (bool) config('sso_user_media.verify_ssl', true),
                'http_errors' => false,
            ]);
    }

    /**
     * data jawaban sukses; gagal = UserMediaException dengan reason dari Master Data
     *
     * @return array<string, mixed>
     */
    protected function data(Response $response): array
    {
        $data = (array) ($response->json('data') ?? []);
        if ($response->successful()) {
            return $data;
        }

        throw new UserMediaException((string) ($data['message'] ?? 'Master Data menjawab HTTP '.$response->status().'.'),
            (string) ($data['reason'] ?? 'http_'.$response->status()), $response->status(), $data);
    }

    protected function assertType(string $type): void
    {
        if (! in_array($type, self::TYPES, true)) {
            throw new UserMediaException('Jenis gambar tidak dikenal: '.$type, 'unknown_type');
        }
    }

    protected function email(string $email): string
    {
        return strtolower(trim($email));
    }
}
