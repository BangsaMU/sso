<?php

namespace Bangsamu\Sso\UserMedia;

use Illuminate\Support\Facades\File;

/**
 * Salinan lokal gambar user dari Master Data (prinsip: halaman dan PDF tidak bergantung pada Master Data saat dibuka).
 * File <cache_path>/<type>/<sha256 email>.png + meta .json (sha256 = ETag, pixel_hash, waktu cek). Isinya hanya cache:
 * server baru cukup mengunduh ulang.
 *
 * - Cache lebih muda dari revalidate_after (10 menit) dipakai langsung.
 * - Lebih tua: diperiksa ulang dengan If-None-Match (timeout pendek). 304 = tetap, 200 = diganti, 404 = dihapus.
 * - Master Data gagal: cache terakhir tetap dipakai. Tanpa cache dan Master Data tidak terjangkau: UserMediaException
 *   (isUnavailable) supaya render PDF ditunda, bukan dicetak tanpa tanda tangan (K3).
 */
class UserMediaCache
{
    public function __construct(protected UserMediaClient $client) {}

    /**
     * Path file lokal untuk dipakai halaman/PDF; null = Master Data menyatakan gambar tidak ada.
     *
     * @throws UserMediaException bila belum ada cache dan Master Data tidak terjangkau
     */
    public function path(string $type, string $email, bool $fresh = false): ?string
    {
        $meta = $this->meta($type, $email);
        $file = $this->filePath($type, $email);
        $cached = is_array($meta) && (! ($meta['exists'] ?? false) || is_file($file));

        if ($cached && ! $fresh && (now()->getTimestamp() - (int) ($meta['checked_at'] ?? 0)) < (int) config('sso_user_media.revalidate_after', 600)) {
            return $meta['exists'] ? $file : null;
        }

        try {
            $result = $this->client->download($type, $email, $cached && ($meta['exists'] ?? false) ? ($meta['sha256'] ?? null) : null);
        } catch (UserMediaException $e) {
            if ($cached) {
                return $meta['exists'] ? $file : null;
            }
            throw $e;
        }

        if ($result['status'] === 304 && $cached) {
            $this->writeMeta($type, $email, array_merge($meta, ['checked_at' => now()->getTimestamp()]));

            return $file;
        }
        if ($result['status'] === 404) {
            $this->forget($type, $email);
            $this->writeMeta($type, $email, ['exists' => false, 'checked_at' => now()->getTimestamp()]);

            return null;
        }

        $this->remember($type, $email, (string) $result['body'], [
            'pixel_hash' => $result['pixel_hash'],
            'uploaded_at' => $result['uploaded_at'],
            'source_app' => $result['source_app'],
        ]);

        return $file;
    }

    /**
     * Meta cache setelah memastikan isinya (lihat path()): exists, sha256, pixel_hash, uploaded_at, source_app, checked_at.
     * Dipakai untuk sidik jari PDF (sha256 berubah = PDF dirender ulang).
     *
     * @return array<string, mixed>
     */
    public function status(string $type, string $email, bool $fresh = false): array
    {
        $this->path($type, $email, $fresh);

        return $this->meta($type, $email) ?? ['exists' => false];
    }

    /** simpan isi PNG yang baru diketahui (mis. sesudah commit: preview kandidat dari check) tanpa menunggu cek ulang */
    public function remember(string $type, string $email, string $png, array $meta = []): void
    {
        $file = $this->filePath($type, $email);
        File::ensureDirectoryExists(dirname($file));
        $tmp = $file.'.'.getmypid().'.tmp';
        file_put_contents($tmp, $png);
        rename($tmp, $file);

        $this->writeMeta($type, $email, array_merge($meta, [
            'exists' => true,
            'sha256' => hash('sha256', $png),
            'bytes' => strlen($png),
            'checked_at' => now()->getTimestamp(),
        ]));
    }

    public function forget(string $type, string $email): void
    {
        @unlink($this->filePath($type, $email));
        @unlink($this->metaPath($type, $email));
    }

    /** @return array<string, mixed>|null */
    public function meta(string $type, string $email): ?array
    {
        $path = $this->metaPath($type, $email);
        if (! is_file($path)) {
            return null;
        }
        $meta = json_decode((string) file_get_contents($path), true);

        return is_array($meta) ? $meta : null;
    }

    public function filePath(string $type, string $email): string
    {
        return $this->base($type).'/'.$this->name($email).'.png';
    }

    protected function metaPath(string $type, string $email): string
    {
        return $this->base($type).'/'.$this->name($email).'.json';
    }

    protected function writeMeta(string $type, string $email, array $meta): void
    {
        $path = $this->metaPath($type, $email);
        File::ensureDirectoryExists(dirname($path));
        $tmp = $path.'.'.getmypid().'.tmp';
        file_put_contents($tmp, json_encode($meta, JSON_UNESCAPED_SLASHES));
        rename($tmp, $path);
    }

    protected function base(string $type): string
    {
        if (! in_array($type, UserMediaClient::TYPES, true)) {
            throw new UserMediaException('Jenis gambar tidak dikenal: '.$type, 'unknown_type');
        }

        return rtrim((string) config('sso_user_media.cache_path', storage_path('framework/cache/user-media')), '/').'/'.$type;
    }

    protected function name(string $email): string
    {
        return hash('sha256', strtolower(trim($email)));
    }
}
