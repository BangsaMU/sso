{{--
    Banner merah bila Master Data / penyimpanan gambar tidak bisa dipakai (paket bangsamu/sso). Pakai di halaman upload:
      @include('sso::user-media.health-alert')                       health dari cache 60 detik (?user_media_recheck=1 = cek ulang)
      @include('sso::user-media.health-alert', ['health' => $health, 'showErrors' => true, 'retryUrl' => ...])
    Variabel $userMediaLocked (bool) tersedia sesudahnya untuk mengunci tombol upload. Server tetap wajib menolak upload
    (UserMediaClient::assertWritable melempar UserMediaException 'unhealthy').
--}}
@php
    $userMediaHealth = $health ?? app(\Bangsamu\Sso\UserMedia\UserMediaClient::class)->health(request()->boolean('user_media_recheck'));
    $userMediaLocked = ! ($userMediaHealth['ok'] ?? false);
@endphp
@if ($userMediaLocked)
    <div class="alert alert-danger shadow-sm" role="alert" data-user-media-health="fail">
        <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:.5rem;">
            <div>
                <strong><i class="fas fa-exclamation-triangle"></i> Server Master Data / penyimpanan gambar tidak dapat dihubungi</strong>
                <div>Upload dan hapus signature, paraf, dan foto dikunci sampai pulih. Gambar yang sudah ada tetap dipakai dari cache aplikasi ini.</div>
                @if (! empty($showErrors) && ! empty($userMediaHealth['errors']))
                    <ul class="mb-0 small">
                        @foreach ($userMediaHealth['errors'] as $userMediaError)
                            <li>{{ $userMediaError }}</li>
                        @endforeach
                    </ul>
                @endif
            </div>
            <a href="{{ $retryUrl ?? request()->fullUrlWithQuery(['user_media_recheck' => 1]) }}" class="btn btn-sm btn-light">
                <i class="fas fa-sync-alt"></i> Cek Ulang Koneksi
            </a>
        </div>
    </div>
@endif
