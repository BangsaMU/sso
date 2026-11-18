# sso

Integrasikan CLAY dengan fitur sso 
- bug fix login via token error session

## Lupa / Reset Password saat server SSO bermasalah (v1.1.25)

- Timeout / koneksi ditolak / jawaban bukan HTTP 200 / SSO gagal mengirim email reset = pesan "coba lagi" (dulu error
  500, "Please wait before retrying", atau "email tidak ditemukan").
- `Bangsamu\Sso\Support\SsoOutage` menghitung gagal beruntun (cache). Mulai `SsoConfig.outage.threshold` (bawaan 3) dalam
  `SsoConfig.outage.window_minutes` (bawaan 15) pesan berubah menjadi "maintenance". Jawaban normal mengosongkan hitungan.
- Setiap gagal memicu event `Bangsamu\Sso\Events\SsoServerUnavailable` (`reachedThreshold()`); app boleh mendengarkannya,
  mis. untuk email ke admin. Pesan bisa diganti lewat `SsoConfig.outage.messages.{unavailable,mail_failed,maintenance}`.

## Gambar user Master Data: signature, paraf, foto profil (v1.2.0, rancangan 2026-11-18)

Signature, paraf, dan foto profil disimpan sekali di bucket MinIO milik Master Data (`app03`) dan dipakai semua aplikasi
SSO. **Hanya Master Data yang menulis bucket**; aplikasi memakai client paket ini (API `api/user-media/*` Master Data) dan
menyimpan cache lokal. Kontrak API dan format token: `master-data/docs/api-user-media.md`.

### Pasang

1. `.env` aplikasi:
   ```
   USER_MEDIA_URL=https://cms.meindo.com:9002     # dev: Master Data dev (MinIO dev sendiri), JANGAN produksi
   MASTER_APP_PRIVATE_KEY=                        # diisi perintah di bawah
   # USER_MEDIA_APP_CODE=APP32                    # bawaan SsoConfig.main.APP_CODE
   ```
2. `php artisan sso:app-key --write` → kunci privat Ed25519 ditulis ke `.env`, kunci publik + fingerprint + perintah
   pendaftaran dicetak. `php artisan config:clear`.
3. Daftarkan kunci publik di Master Data: **Apps → aplikasi → tab Kunci API**, atau di server Master Data
   `php artisan master:app-key --register=APP32 --public=<kunci> --scope=user_media`. Cocokkan fingerprint.
4. Tabel konflik (hanya bila memakai sinkron data lama): `php artisan vendor:publish --tag=sso-user-media-migrations`,
   lalu jalankan file migration itu (`migrate --path=...`).

Rotasi kunci: `sso:app-key --write --force`, daftarkan kunci baru di Master Data, `config:clear`, cabut kunci lama.
`sso:app-key --show` mencetak kunci publik + fingerprint dari kunci yang terpasang.

### Pakai

```php
use Bangsamu\Sso\UserMedia\UserMediaCache;
use Bangsamu\Sso\UserMedia\UserMediaClient;
use Bangsamu\Sso\UserMedia\UserMediaException;

// halaman/PDF: file lokal (cache 10 menit, lalu If-None-Match ke Master Data; Master Data mati = cache terakhir)
$path = app(UserMediaCache::class)->path('signature', $user->email);   // null = belum punya
$meta = app(UserMediaCache::class)->status('signature', $user->email); // sha256 untuk sidik jari PDF

// upload (izin di aplikasi: diri sendiri / admin update_user)
$client = app(UserMediaClient::class);
$check = $client->check('signature', $owner->email, auth()->user()->email, file_get_contents($file));
if (! $check['master_exists']) {
    $client->commit('signature', $owner->email, auth()->user()->email, $check['check_token']);
} elseif ($check['requires_confirmation']) {
    // tampilkan modal berdampingan; setelah centang: commit(..., $check['check_token'], true)
}
```

- Semua penulisan (`check`, `commit`, `delete`) didahului `assertWritable()`: health Master Data OK (cache 60 detik) dan
  **bukan aplikasi dev yang menulis ke Master Data produksi** (`APP_ENV` bukan production tetapi health `env=production`
  → `UserMediaException` reason `dev_to_production_blocked`).
- `UserMediaException`: `reason` = kode Master Data (`replace_requires_confirmation`, `invalid_image`, `owner_inactive`,
  `invalid_token`, …) atau client (`not_configured`, `unreachable`, `unhealthy`). `isUnavailable()` = Master Data tidak
  bisa dipakai: kunci upload; render PDF tanpa cache **ditunda** (job `release`), bukan dicetak tanpa tanda tangan (K3).
  `MASTER_APP_PRIVATE_KEY` yang terisi tetapi rusak (bukan base64 64 byte) juga `not_configured` (sejak v1.2.1; dulu
  `InvalidArgumentException` lolos dari client dan halaman app error 500); health memuat pesan "MASTER_APP_PRIVATE_KEY
  tidak valid", buat ulang dengan `php artisan sso:app-key --write --force`.
- Sesudah commit, perbarui cache: `UserMediaCache::path($type, $email, true)` (atau `remember()` dengan PNG preview).

### Komponen Blade (Bootstrap 4 atau 5)

```blade
@include('sso::user-media.health-alert')        {{-- banner merah + Cek Ulang Koneksi; $userMediaLocked untuk kunci tombol --}}
@include('sso::user-media.compare-modal')       {{-- JS: SsoUserMedia.compare(dataCheck, {label, onReplace, onKeep}) --}}
@include('sso::user-media.conflict-banner')     {{-- untuk user login yang punya konflik; link config sso_user_media.conflict_url --}}
```

### Sinkron gambar lama

`php artisan sso:user-media-sync [--type=] [--email=] [--dry-run] [--yes]`. Aturan: Master Data kosong = diisi; sama =
`markSynced`; berbeda = **tidak ditimpa**, dicatat di `user_media_conflicts` untuk dipilih pemilik akun (selama belum dipilih
aplikasi tetap memakai gambar lokal); file hilang / bukan gambar / akun tidak ada = dilewati, masuk laporan. Bucket + env
tujuan ditampilkan dan wajib dikonfirmasi. Mulai dengan `--dry-run`.

**Sumber bawaan (tanpa class buatan aplikasi):** bila `legacy_source` kosong dipakai `Bangsamu\Sso\UserMedia\UserDetailsLegacySource`:
tabel `user_details` (`field_key` signature / paraf / profile_photo, `field_value` = path file). Yang berbeda antar aplikasi
diatur lewat config `sso_user_media.legacy` / .env:

| .env | Bawaan | Arti |
|---|---|---|
| `USER_MEDIA_LEGACY_ROOTS` | `.,media,app,app/public,disk:media,disk:public` | folder pencarian berurutan (absolut, relatif `storage/`, `.` = `storage/`, `disk:<nama>`); file pertama yang ada dipakai |
| `USER_MEDIA_LEGACY_EMAIL` | `user_email` | kolom email, atau `users.email` (join `users.id = user_id`) |
| `USER_MEDIA_LEGACY_PICK` | `latest` | beberapa baris satu jenis: `latest` (id terbesar) / `first` (id terkecil) |
| `USER_MEDIA_LEGACY_ON_SYNCED` | `keep` | `keep` = nilai lokal tetap; `ref` = diganti `app03:<type>` |
| `USER_MEDIA_LEGACY_TABLE` | `user_details` | nama tabel |

Path yang tidak ketemu di folder mana pun = "File lokal hilang" (dilewati, bukan error). Bila sebagian besar file tidak
ketemu, perintah memperingatkan sebelum menulis, lengkap dengan path yang dicari, karena biasanya folder pencariannya yang
salah. Pekerjaan tambahan setelah sinkron (Activity Log, cache status) cukup lewat listener event
`Bangsamu\Sso\UserMedia\Events\LegacyUserMediaSynced` (`$item`, `$media`).

**Sumber sendiri** hanya bila gambar disimpan dengan cara lain (base64 di DB, tabel berbeda, S3/URL): `USER_MEDIA_LEGACY_SOURCE`
/ `legacy_source` = class yang mengimplementasikan `Bangsamu\Sso\UserMedia\Contracts\LegacyUserMediaSource` (`items()` =
`LegacyUserMedia(email, type, path, localRef, userId, searched)`, `markSynced()`).

### Rujukan `app03:` di api/getSignature, api/getParaf

Paket ini mendaftarkan `Bangsamu\Master\Contracts\UserMediaResolver` (bila bangsamu/master versi yang memilikinya terpasang):
nilai user_details berawalan `app03:` dibaca dari cache gambar Master Data. Tanpa client terpasang / Master Data mati tanpa
cache = 503 (coba lagi), gambar tidak ada = 403.

### Test paket

`composer install` lalu `vendor/bin/phpunit` (testbench, sqlite memory, HTTP Master Data di-fake).
