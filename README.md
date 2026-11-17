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
