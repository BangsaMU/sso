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

    // sumber gambar lama untuk `php artisan sso:user-media-sync`. Kosong = sumber bawaan
    // Bangsamu\Sso\UserMedia\UserDetailsLegacySource (tabel user_details, diatur lewat 'legacy' di bawah). Isi class sendiri
    // (implements Bangsamu\Sso\UserMedia\Contracts\LegacyUserMediaSource) hanya bila gambar disimpan dengan cara lain
    // (base64 di DB, tabel berbeda, S3/URL luar).
    'legacy_source' => env('USER_MEDIA_LEGACY_SOURCE'),

    // pengaturan sumber bawaan (UserDetailsLegacySource)
    'legacy' => [
        // tabel + kolom: satu baris per user per jenis (field_key = signature / paraf / profile_photo, field_value = path file)
        'table' => env('USER_MEDIA_LEGACY_TABLE', 'user_details'),
        'key_column' => 'field_key',
        'value_column' => 'field_value',
        // email pemilik: nama kolom di tabel itu, atau 'users.email' (join users.id = user_id) bila kolom email bisa usang
        'email' => env('USER_MEDIA_LEGACY_EMAIL', 'user_email'),
        'user_id_column' => 'user_id',
        'users_table' => 'users',
        // baris terhapus (kolom tidak ada = diabaikan)
        'soft_delete_column' => 'deleted_at',
        // user punya beberapa baris satu jenis: latest = id terbesar, first = id terkecil
        'pick' => env('USER_MEDIA_LEGACY_PICK', 'latest'),
        // folder tempat path dicari berurutan, file pertama yang ada dipakai: absolut, relatif storage/ ('.' = storage/ itu
        // sendiri), atau disk:<nama>. Pisah koma di .env. Bawaan mencakup /media/... relatif storage/ dan disk media.
        'roots' => env('USER_MEDIA_LEGACY_ROOTS', '.,media,app,app/public,disk:media,disk:public'),
        // setelah sama / diisi: keep = nilai lokal tetap (aplikasi memakai file sendiri), ref = diganti 'app03:<type>'
        'on_synced' => env('USER_MEDIA_LEGACY_ON_SYNCED', 'keep'),
        'ref_prefix' => 'app03:',
    ],

    // halaman aplikasi untuk memilih gambar saat konflik (banner konflik), mis. route('profile.media')
    'conflict_url' => null,
];
