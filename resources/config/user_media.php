<?php

/*
|--------------------------------------------------------------------------
| Client gambar user Master Data (signature, paraf, foto profil)
|--------------------------------------------------------------------------
|
| Gambar disimpan sekali di bucket MinIO milik Master Data dan dipakai semua aplikasi SSO. Aplikasi ini hanya lewat API
| Master Data (api/user-media/*) dengan token yang ditandatangani kunci privat Ed25519 aplikasi ini, dan menyimpan salinan
| cache lokal supaya halaman/PDF tidak bergantung pada Master Data saat dibuka. Kontrak: master-data docs/api-user-media.md.
| Dibaca sebagai config('sso_user_media.*'); timpa lewat .env atau publish (php artisan vendor:publish --tag=sso-user-media).
|
*/

return [
    // URL Master Data (tanpa /api). Dev diarahkan ke Master Data dev (yang memakai MinIO dev sendiri), BUKAN ke produksi.
    'url' => env('USER_MEDIA_URL'),

    // APP_CODE aplikasi ini (klaim iss). Kosong = SsoConfig.main.APP_CODE.
    'app_code' => env('USER_MEDIA_APP_CODE'),

    // kunci privat Ed25519 base64 (64 byte), dibuat `php artisan sso:app-key --write`. Rahasia: hanya di .env.
    'private_key' => env('MASTER_APP_PRIVATE_KEY'),

    // batas waktu request (detik): baca/health pendek, upload lebih panjang
    'timeout' => (float) env('USER_MEDIA_TIMEOUT', 3),
    'connect_timeout' => (float) env('USER_MEDIA_CONNECT_TIMEOUT', 2),
    'upload_timeout' => (float) env('USER_MEDIA_UPLOAD_TIMEOUT', 20),
    'verify_ssl' => (bool) env('USER_MEDIA_VERIFY_SSL', true),

    // umur token (detik, maksimal 60 di Master Data)
    'token_ttl' => 50,

    // hasil health di-cache (detik)
    'health_cache_seconds' => 60,

    // cache lokal gambar: file <type>/<sha256 email>.png + .json meta; diperiksa ulang (If-None-Match) bila lebih tua dari ini
    'cache_path' => env('USER_MEDIA_CACHE_PATH', storage_path('framework/cache/user-media')),
    'revalidate_after' => (int) env('USER_MEDIA_REVALIDATE_AFTER', 600),

    // penjaga dev: APP_ENV aplikasi ini bukan production tetapi Master Data menjawab env production = tulis ditolak
    'block_dev_to_production' => true,

    // sumber gambar lama untuk `php artisan sso:user-media-sync`: class yang mengimplementasikan
    // Bangsamu\Sso\UserMedia\Contracts\LegacyUserMediaSource (disediakan aplikasi, mis. App\Support\SpbUserMediaSource)
    'legacy_source' => null,

    // halaman aplikasi untuk memilih gambar saat konflik (banner konflik), mis. route('profile.media')
    'conflict_url' => null,
];
