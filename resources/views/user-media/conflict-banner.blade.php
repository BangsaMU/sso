{{--
    Banner untuk user login yang gambar lamanya di aplikasi ini berbeda dengan di Master Data (hasil sso:user-media-sync).
    Pakai di layout / Dashboard: @include('sso::user-media.conflict-banner')  (opsional ['url' => route(...)]).
    Selama belum dipilih, aplikasi tetap memakai gambar lokal (K4).
--}}
@php
    $userMediaConflicts = collect();
    if (auth()->check() && cache()->remember('sso_user_media_conflicts_table', 600, fn () => \Illuminate\Support\Facades\Schema::hasTable('user_media_conflicts'))) {
        $userMediaConflicts = \Bangsamu\Sso\UserMedia\UserMediaConflict::query()->open()->forEmail((string) auth()->user()->email)->get();
    }
    $userMediaLabels = ['signature' => 'tanda tangan', 'paraf' => 'paraf', 'profile_photo' => 'foto profil'];
@endphp
@if ($userMediaConflicts->isNotEmpty())
    <div class="alert alert-warning shadow-sm" role="alert" data-user-media-conflict="{{ $userMediaConflicts->count() }}">
        <i class="fas fa-exclamation-circle"></i>
        {{ ucfirst($userMediaConflicts->map(fn ($c) => $userMediaLabels[$c->type] ?? $c->type)->unique()->implode(', ')) }} Anda di aplikasi ini
        berbeda dengan di Master Data. Pilih yang dipakai; sampai dipilih, aplikasi ini tetap memakai gambar lokal.
        @if ($userMediaConflictUrl = ($url ?? config('sso_user_media.conflict_url')))
            <a href="{{ $userMediaConflictUrl }}" class="btn btn-sm btn-warning ml-2 ms-2">Pilih sekarang</a>
        @endif
    </div>
@endif
