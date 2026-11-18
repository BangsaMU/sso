<?php

namespace Bangsamu\Sso\Tests\Feature;

use Bangsamu\Sso\Tests\TestCase;
use Bangsamu\Sso\UserMedia\Contracts\LegacyUserMediaSource;
use Bangsamu\Sso\UserMedia\LegacyUserMedia;
use Bangsamu\Sso\UserMedia\UserMediaConflict;
use Bangsamu\Sso\UserMedia\UserMediaToken;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

/**
 * sso:app-key (kunci API) dan sso:user-media-sync (gambar lama → Master Data dengan aturan rancangan).
 */
class UserMediaCommandsTest extends TestCase
{
    public function test_app_key_mencetak_dan_menulis_env_tanpa_menimpa(): void
    {
        $this->artisan('sso:app-key', ['--format' => 'env'])
            ->expectsOutputToContain('MASTER_APP_PRIVATE_KEY=')
            ->expectsOutputToContain('MASTER_APP_PUBLIC_KEY=')
            ->assertSuccessful();

        $env = sys_get_temp_dir().'/sso-env-'.getmypid();
        file_put_contents($env, "APP_NAME=Uji\n");
        try {
            $this->artisan('sso:app-key', ['--write' => true, '--env-file' => $env])
                ->expectsOutputToContain('master:app-key --register=APP32')
                ->assertSuccessful();
            preg_match('/^MASTER_APP_PRIVATE_KEY=(.+)$/m', file_get_contents($env), $m);
            $public = UserMediaToken::publicKeyFromSecret($m[1]);

            $this->artisan('sso:app-key', ['--write' => true, '--env-file' => $env])->expectsOutputToContain('sudah terisi')->assertFailed();
            $this->artisan('sso:app-key', ['--write' => true, '--force' => true, '--env-file' => $env])->assertSuccessful();
            $this->assertSame(1, substr_count(file_get_contents($env), 'MASTER_APP_PRIVATE_KEY='));
            $this->assertStringContainsString('APP_NAME=Uji', file_get_contents($env));
            $this->assertNotSame($m[1], (preg_match('/^MASTER_APP_PRIVATE_KEY=(.+)$/m', file_get_contents($env), $m2) ? $m2[1] : null), 'rotasi');
            $this->assertNotEmpty($public);
        } finally {
            @unlink($env);
        }

        $this->artisan('sso:app-key', ['--show' => true])
            ->expectsOutputToContain(UserMediaToken::fingerprint($this->publicKey))
            ->assertSuccessful();
    }

    /** sumber uji: kosong (diisi), sama, berbeda (konflik), file hilang, bukan gambar */
    private function siapkanSumber(): array
    {
        $dir = sys_get_temp_dir().'/sso-legacy-'.getmypid();
        @mkdir($dir);
        foreach (['kosong', 'sama', 'beda', 'rusak'] as $nama) {
            file_put_contents("$dir/$nama.png", $nama === 'rusak' ? 'bukan gambar' : $this->png());
        }
        UjiLegacySource::$items = [
            new LegacyUserMedia('kosong@meindo.com', 'signature', "$dir/kosong.png", '/media/signature/a'),
            new LegacyUserMedia('sama@meindo.com', 'signature', "$dir/sama.png", '/media/signature/b'),
            new LegacyUserMedia('beda@meindo.com', 'paraf', "$dir/beda.png", '/media/paraf/c'),
            new LegacyUserMedia('hilang@meindo.com', 'signature', "$dir/tidak-ada.png", '/media/signature/d'),
            new LegacyUserMedia('rusak@meindo.com', 'signature', "$dir/rusak.png", '/media/signature/e'),
        ];
        UjiLegacySource::$synced = [];
        config(['sso_user_media.legacy_source' => UjiLegacySource::class]);

        Http::fake(function (Request $request) {
            $path = parse_url($request->url(), PHP_URL_PATH);
            if ($path === '/api/user-media/health') {
                return Http::response($this->healthOk());
            }
            $owner = $this->claimsOf($request)['sub'] ?? '';
            if (str_ends_with($path, '/check')) {
                return match ($owner) {
                    'kosong@meindo.com' => Http::response(['status' => 'sukses', 'data' => ['master_exists' => false, 'same' => false, 'check_token' => 'tok-kosong',
                        'candidate' => ['pixel_hash' => 'k'], 'master' => ['exists' => false]]]),
                    'sama@meindo.com' => Http::response(['status' => 'sukses', 'data' => ['master_exists' => true, 'same' => true, 'check_token' => null,
                        'candidate' => ['pixel_hash' => 's'], 'master' => ['exists' => true, 'sha256' => 'sha-sama', 'pixel_hash' => 's']]]),
                    'beda@meindo.com' => Http::response(['status' => 'sukses', 'data' => ['master_exists' => true, 'same' => false, 'check_token' => 'tok-beda',
                        'requires_confirmation' => true, 'candidate' => ['pixel_hash' => str_repeat('1', 64)],
                        'master' => ['exists' => true, 'sha256' => str_repeat('9', 64), 'pixel_hash' => str_repeat('2', 64), 'source_app' => 'APP27']]]),
                    default => Http::response(['status' => 'gagal', 'code' => 422, 'data' => ['reason' => 'invalid_image', 'message' => 'File bukan gambar.']], 422),
                };
            }
            if (str_ends_with($path, '/commit')) {
                return Http::response(['status' => 'sukses', 'code' => 201, 'data' => ['result' => 'created', 'media' => ['sha256' => 'sha-baru']]], 201);
            }

            return Http::response([], 500);
        });

        return [$dir];
    }

    public function test_sinkron_mengisi_yang_kosong_menandai_yang_sama_dan_tidak_menimpa_yang_beda(): void
    {
        $this->siapkanSumber();

        $this->artisan('sso:user-media-sync', ['--yes' => true])
            ->expectsOutputToContain('bucket app03-test')
            ->expectsOutputToContain('Konflik (berbeda, tidak ditimpa)')
            ->expectsOutputToContain('File lokal hilang')
            ->assertSuccessful();

        // hanya yang kosong di-commit, tanpa confirm_replace
        Http::assertSent(fn (Request $request) => str_ends_with($request->url(), '/commit')
            && json_decode($request->body(), true) === ['email' => 'kosong@meindo.com', 'check_token' => 'tok-kosong', 'confirm_replace' => false]);
        Http::assertNotSent(fn (Request $request) => str_ends_with($request->url(), '/commit') && str_contains($request->body(), 'tok-beda'));

        $this->assertSame(['kosong@meindo.com' => 'sha-baru', 'sama@meindo.com' => 'sha-sama'], UjiLegacySource::$synced);

        $konflik = UserMediaConflict::query()->open()->forEmail('beda@meindo.com')->firstOrFail();
        $this->assertSame('paraf', $konflik->type);
        $this->assertSame(str_repeat('1', 64), $konflik->local_pixel_hash);
        $this->assertSame(str_repeat('2', 64), $konflik->master_pixel_hash);
        $this->assertSame('/media/paraf/c', $konflik->local_ref);

        // jalan ulang tidak menggandakan konflik
        $this->artisan('sso:user-media-sync', ['--yes' => true])->assertSuccessful();
        $this->assertSame(1, UserMediaConflict::query()->open()->count());
    }

    public function test_dry_run_tanpa_commit_dan_tanpa_catatan(): void
    {
        $this->siapkanSumber();

        $this->artisan('sso:user-media-sync', ['--dry-run' => true])->expectsOutputToContain('Akan diisi (dry-run)')->assertSuccessful();

        Http::assertNotSent(fn (Request $request) => str_ends_with($request->url(), '/commit'));
        $this->assertSame([], UjiLegacySource::$synced);
        $this->assertSame(0, UserMediaConflict::query()->count());
    }

    public function test_tujuan_wajib_dikonfirmasi(): void
    {
        $this->siapkanSumber();

        $this->artisan('sso:user-media-sync')
            ->expectsConfirmation('Kirim gambar lama ke Master Data https://master.test (bucket app03-test)?', 'no')
            ->assertFailed();
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), '/check'));
    }
}

class UjiLegacySource implements LegacyUserMediaSource
{
    /** @var list<LegacyUserMedia> */
    public static array $items = [];

    /** @var array<string, string> email => sha256 Master Data */
    public static array $synced = [];

    public function items(?string $type = null, ?string $email = null): iterable
    {
        return array_filter(self::$items, fn (LegacyUserMedia $item) => ($type === null || $item->type === $type) && ($email === null || $item->email === $email));
    }

    public function markSynced(LegacyUserMedia $item, array $media): void
    {
        self::$synced[$item->email] = (string) ($media['sha256'] ?? '');
    }
}
