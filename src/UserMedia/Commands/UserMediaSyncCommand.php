<?php

namespace Bangsamu\Sso\UserMedia\Commands;

use Bangsamu\Sso\UserMedia\Contracts\LegacyUserMediaSource;
use Bangsamu\Sso\UserMedia\LegacyUserMedia;
use Bangsamu\Sso\UserMedia\UserMediaClient;
use Bangsamu\Sso\UserMedia\UserMediaConflict;
use Bangsamu\Sso\UserMedia\UserMediaException;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;

/**
 * Sinkron gambar lama aplikasi ini ke Master Data (aturan rancangan, sama untuk semua app):
 *   - Master Data kosong          → diisi otomatis (K5), lalu markSynced;
 *   - ada, hash piksel sama       → markSynced, tidak ada yang ditulis;
 *   - ada, berbeda                → TIDAK ditimpa, dicatat di user_media_conflicts untuk dipilih pemilik akun (K4);
 *   - file hilang / bukan gambar / akun tidak ada di Master Data → dilewati, masuk laporan.
 * Sumber: class di config sso_user_media.legacy_source (Contracts\LegacyUserMediaSource). Bucket + env Master Data tujuan
 * ditampilkan dan wajib dikonfirmasi sebelum menulis (--yes untuk skrip). --dry-run: hanya check, tanpa commit/catat.
 */
class UserMediaSyncCommand extends Command
{
    protected $signature = 'sso:user-media-sync
        {--type= : signature, paraf, atau profile_photo (bawaan semua)}
        {--email= : hanya satu email}
        {--dry-run : hanya laporan (check ke Master Data tanpa commit, tanpa catat konflik)}
        {--yes : lewati konfirmasi tujuan (untuk skrip)}
        {--actor=system:user-media-sync : email/tanda pelaku yang dicatat Master Data}';

    protected $description = 'Sinkron signature/paraf/foto lama aplikasi ini ke Master Data tanpa menimpa gambar yang ada';

    private const LABEL = [
        'diisi' => 'Diisi (Master Data kosong)',
        'akan_diisi' => 'Akan diisi (dry-run)',
        'sama' => 'Sama (ditandai sinkron)',
        'konflik' => 'Konflik (berbeda, tidak ditimpa)',
        'file_hilang' => 'File lokal hilang',
        'ditolak' => 'Ditolak Master Data (bukan gambar / akun tidak ada / tidak aktif)',
        'gagal' => 'Gagal',
    ];

    public function handle(UserMediaClient $client): int
    {
        $sourceClass = config('sso_user_media.legacy_source');
        if (! $sourceClass || ! is_subclass_of($sourceClass, LegacyUserMediaSource::class)) {
            $this->error('Isi config sso_user_media.legacy_source dengan class yang mengimplementasikan '.LegacyUserMediaSource::class.'.');

            return self::FAILURE;
        }
        $type = $this->option('type') ?: null;
        if ($type !== null && ! in_array($type, UserMediaClient::TYPES, true)) {
            $this->error('--type harus salah satu dari: '.implode(', ', UserMediaClient::TYPES));

            return self::FAILURE;
        }
        $dryRun = (bool) $this->option('dry-run');
        if (! $dryRun && ! Schema::hasTable('user_media_conflicts')) {
            $this->error('Tabel user_media_conflicts belum ada: php artisan vendor:publish --tag=sso-user-media-migrations lalu migrate file itu.');

            return self::FAILURE;
        }

        try {
            $client->assertWritable();
        } catch (UserMediaException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }
        $health = $client->health();
        $this->line('Tujuan : Master Data '.$client->baseUrl().', bucket '.($health['bucket'] ?? '?').', env '.($health['env'] ?? '?'));
        $this->line('Mode   : '.($dryRun ? 'DRY-RUN (tanpa commit)' : 'TULIS (gambar yang ada di Master Data tidak pernah ditimpa)'));
        if (! $dryRun && ! $this->option('yes')
            && ! $this->confirm('Kirim gambar lama ke Master Data '.$client->baseUrl().' (bucket '.($health['bucket'] ?? '?').')?', false)) {
            $this->warn('Dibatalkan, tidak ada yang dikirim.');

            return self::FAILURE;
        }

        /** @var LegacyUserMediaSource $source */
        $source = app($sourceClass);
        $actor = (string) $this->option('actor');
        $hasil = [];

        foreach ($source->items($type, $this->option('email') ?: null) as $item) {
            $status = $this->syncOne($client, $source, $item, $actor, $dryRun, $info);
            $hasil[] = ['status' => $status, 'email' => strtolower($item->email), 'type' => $item->type, 'info' => $info];
            if ($status === 'gagal' && str_contains($info, 'tidak dapat dihubungi')) {
                $this->error('Master Data tidak terjangkau, sinkron dihentikan: '.$info);
                break;
            }
        }

        $this->laporan($hasil);
        Log::info('[sso:user-media-sync] '.($dryRun ? 'dry-run ' : '').collect($hasil)->countBy('status')->toJson());

        return self::SUCCESS;
    }

    private function syncOne(UserMediaClient $client, LegacyUserMediaSource $source, LegacyUserMedia $item, string $actor, bool $dryRun, ?string &$info): string
    {
        $info = '';
        if ($item->path === null || ! is_file($item->path) || ! is_readable($item->path)) {
            $info = (string) ($item->path ?? $item->localRef);

            return 'file_hilang';
        }

        try {
            $check = $client->check($item->type, $item->email, $actor, (string) file_get_contents($item->path), basename($item->path));
            if ($check['same'] ?? false) {
                if (! $dryRun) {
                    $source->markSynced($item, (array) ($check['master'] ?? []));
                }

                return 'sama';
            }
            if ($check['master_exists'] ?? false) {
                $info = 'lokal '.substr((string) ($check['candidate']['pixel_hash'] ?? ''), 0, 12).' / Master Data '
                    .substr((string) ($check['master']['pixel_hash'] ?? ''), 0, 12).' ('.($check['master']['source_app'] ?? '?').')';
                if (! $dryRun) {
                    UserMediaConflict::query()->updateOrCreate(
                        ['email' => strtolower(trim($item->email)), 'type' => $item->type, 'resolved_at' => null],
                        [
                            'local_ref' => $item->localRef,
                            'local_path' => $item->path,
                            'local_pixel_hash' => $check['candidate']['pixel_hash'] ?? null,
                            'master_pixel_hash' => $check['master']['pixel_hash'] ?? null,
                            'master_sha256' => $check['master']['sha256'] ?? null,
                            'found_at' => now(),
                        ]
                    );
                }

                return 'konflik';
            }
            if ($dryRun) {
                return 'akan_diisi';
            }
            $commit = $client->commit($item->type, $item->email, $actor, (string) $check['check_token'], false);
            $source->markSynced($item, (array) ($commit['media'] ?? []));

            return $commit['result'] === 'same' ? 'sama' : 'diisi';
        } catch (UserMediaException $e) {
            $info = $e->getMessage();
            if (in_array($e->reason, ['invalid_image', 'owner_not_found', 'owner_inactive', 'file_too_large'], true)) {
                return 'ditolak';
            }
            if ($e->reason === 'replace_requires_confirmation') {
                // gambar Master Data muncul di antara check dan commit: jangan timpa
                return 'konflik';
            }

            return 'gagal';
        }
    }

    /** @param  list<array{status: string, email: string, type: string, info: string}>  $hasil */
    private function laporan(array $hasil): void
    {
        $hitung = collect($hasil)->countBy('status');
        $this->newLine();
        $this->table(['Hasil', 'Jumlah'], collect(self::LABEL)->filter(fn ($label, $status) => $hitung->has($status))
            ->map(fn ($label, $status) => [$label, $hitung[$status]])->values()->all() ?: [['(tidak ada data)', 0]]);

        $perluDicek = collect($hasil)->whereNotIn('status', ['diisi', 'akan_diisi', 'sama']);
        if ($perluDicek->isNotEmpty()) {
            $this->warn('Perlu ditindaklanjuti:');
            $this->table(['Hasil', 'Jenis', 'Email', 'Keterangan'],
                $perluDicek->map(fn ($r) => [self::LABEL[$r['status']], $r['type'], $r['email'], mb_substr($r['info'], 0, 120)])->values()->all());
        }
    }
}
