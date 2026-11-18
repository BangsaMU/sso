<?php

namespace Bangsamu\Sso\Tests\Feature;

use Bangsamu\Sso\Tests\TestCase;
use Bangsamu\Sso\UserMedia\Events\LegacyUserMediaSynced;
use Bangsamu\Sso\UserMedia\LegacyUserMedia;
use Bangsamu\Sso\UserMedia\UserDetailsLegacySource;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;

/**
 * Sumber bawaan sso:user-media-sync: tabel user_details, folder pencarian dari config, tanpa class buatan aplikasi.
 */
class UserDetailsLegacySourceTest extends TestCase
{
    private string $storageRoot;

    private string $diskRoot;

    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('email');
        });
        Schema::create('user_details', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('user_email')->nullable();
            $table->string('field_key');
            $table->string('field_value')->nullable();
            $table->softDeletes();
        });

        // pola SPB: /media/<type>/... relatif storage; pola GDA: <folder>/... relatif disk media
        $this->storageRoot = sys_get_temp_dir().'/sso-legacy-storage-'.getmypid();
        $this->diskRoot = sys_get_temp_dir().'/sso-legacy-disk-'.getmypid();
        File::ensureDirectoryExists($this->storageRoot.'/media/paraf');
        File::ensureDirectoryExists($this->diskRoot.'/signatures');
        file_put_contents($this->storageRoot.'/media/paraf/spb.png', $this->png());
        file_put_contents($this->diskRoot.'/signatures/gda.png', $this->png('biru'));
        config([
            'filesystems.disks.media' => ['driver' => 'local', 'root' => $this->diskRoot],
            'sso_user_media.legacy.roots' => $this->storageRoot.',disk:media',
        ]);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->storageRoot);
        File::deleteDirectory($this->diskRoot);
        parent::tearDown();
    }

    public function test_path_dari_beberapa_pola_terbaca_tanpa_diatur_satu_per_satu(): void
    {
        $this->detail(1, 'spb@meindo.com', 'paraf', '/media/paraf/spb.png');
        $this->detail(2, 'gda@meindo.com', 'signature', 'signatures/gda.png');
        $this->detail(3, 'hilang@meindo.com', 'signature', 'signatures/tidak-ada.png');
        $this->detail(4, 'ref@meindo.com', 'signature', 'app03:signature');
        $this->detail(5, 'hapus@meindo.com', 'signature', 'signatures/gda.png', deleted: true);

        $items = collect(app(UserDetailsLegacySource::class)->items())->keyBy('email');

        $this->assertSame(['gda@meindo.com', 'hilang@meindo.com', 'spb@meindo.com'], $items->keys()->all());
        $this->assertSame($this->storageRoot.'/media/paraf/spb.png', $items['spb@meindo.com']->path);
        $this->assertSame($this->diskRoot.'/signatures/gda.png', $items['gda@meindo.com']->path);
        $this->assertSame('signatures/gda.png', $items['gda@meindo.com']->localRef);
        $this->assertSame(2, $items['gda@meindo.com']->userId);
        $this->assertNull($items['hilang@meindo.com']->path);
        $this->assertSame([$this->storageRoot.'/signatures/tidak-ada.png', $this->diskRoot.'/signatures/tidak-ada.png'], $items['hilang@meindo.com']->searched);

        $this->assertSame(['gda@meindo.com'], collect(app(UserDetailsLegacySource::class)->items('signature', 'GDA@meindo.com'))->pluck('email')->all());
    }

    public function test_email_dari_users_pilihan_baris_dan_path_berbahaya(): void
    {
        DB::table('users')->insert(['id' => 7, 'email' => 'baru@meindo.com']);
        $this->detail(7, 'lama@meindo.com', 'signature', 'signatures/pertama.png');
        $this->detail(7, 'lama@meindo.com', 'signature', 'signatures/gda.png');
        $this->detail(8, 'jahat@meindo.com', 'signature', '../../etc/passwd');

        $latest = collect(app(UserDetailsLegacySource::class)->items())->keyBy('email');
        $this->assertSame('signatures/gda.png', $latest['lama@meindo.com']->localRef);
        $this->assertNull($latest['jahat@meindo.com']->path);
        $this->assertSame([], $latest['jahat@meindo.com']->searched);

        config(['sso_user_media.legacy.email' => 'users.email', 'sso_user_media.legacy.pick' => 'first']);
        $items = collect(app(UserDetailsLegacySource::class)->items())->keyBy('email');
        $this->assertSame(['baru@meindo.com'], $items->keys()->all(), 'user tanpa baris users dilewati, email dari users');
        $this->assertSame('signatures/pertama.png', $items['baru@meindo.com']->localRef);
    }

    public function test_mark_synced_keep_atau_ganti_rujukan(): void
    {
        $this->detail(2, 'gda@meindo.com', 'signature', 'signatures/gda.png');
        $source = app(UserDetailsLegacySource::class);
        $item = new LegacyUserMedia('gda@meindo.com', 'signature', $this->diskRoot.'/signatures/gda.png', 'signatures/gda.png', 2);

        $source->markSynced($item, ['sha256' => 'x']);
        $this->assertSame('signatures/gda.png', DB::table('user_details')->value('field_value'));

        config(['sso_user_media.legacy.on_synced' => 'ref']);
        $source->markSynced($item, ['sha256' => 'x']);
        $this->assertSame('app03:signature', DB::table('user_details')->value('field_value'));
    }

    public function test_perintah_memakai_sumber_bawaan_mengirim_event_dan_memperingatkan_folder_salah(): void
    {
        config(['sso_user_media.legacy_source' => null]);
        $this->detail(2, 'gda@meindo.com', 'signature', 'signatures/gda.png');
        Event::fake([LegacyUserMediaSynced::class]);
        Http::fake(function (Request $request) {
            $path = parse_url($request->url(), PHP_URL_PATH);
            if ($path === '/api/user-media/health') {
                return Http::response($this->healthOk());
            }
            if (str_ends_with($path, '/check')) {
                return Http::response(['status' => 'sukses', 'data' => ['master_exists' => true, 'same' => true, 'check_token' => null,
                    'candidate' => ['pixel_hash' => 's'], 'master' => ['exists' => true, 'sha256' => 'sha-sama']]]);
            }

            return Http::response([], 500);
        });

        $this->artisan('sso:user-media-sync', ['--yes' => true])
            ->expectsOutputToContain('Sumber : '.UserDetailsLegacySource::class)
            ->expectsOutputToContain('Sama (ditandai sinkron)')
            ->assertSuccessful();
        Event::assertDispatched(LegacyUserMediaSynced::class, fn (LegacyUserMediaSynced $event) => $event->item->email === 'gda@meindo.com'
            && $event->media['sha256'] === 'sha-sama');

        foreach ([3, 4, 5] as $id) {
            $this->detail($id, "hilang{$id}@meindo.com", 'signature', "signatures/hilang{$id}.png");
        }
        $this->artisan('sso:user-media-sync', ['--dry-run' => true])
            ->expectsOutputToContain('3 dari 4 file lokal tidak ditemukan')
            ->expectsOutputToContain($this->diskRoot.'/signatures/hilang3.png')
            ->expectsOutputToContain('USER_MEDIA_LEGACY_ROOTS')
            ->assertSuccessful();
    }

    public function test_class_sumber_yang_salah_tetap_ditolak(): void
    {
        config(['sso_user_media.legacy_source' => \stdClass::class]);

        $this->artisan('sso:user-media-sync', ['--dry-run' => true])
            ->expectsOutputToContain('Kosongkan untuk memakai sumber bawaan')
            ->assertFailed();
    }

    private function detail(int $userId, string $email, string $type, string $value, bool $deleted = false): void
    {
        DB::table('user_details')->insert([
            'user_id' => $userId, 'user_email' => $email, 'field_key' => $type, 'field_value' => $value,
            'deleted_at' => $deleted ? now() : null,
        ]);
    }
}
