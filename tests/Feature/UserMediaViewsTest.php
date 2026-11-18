<?php

namespace Bangsamu\Sso\Tests\Feature;

use Bangsamu\Master\Contracts\UserMediaResolver;
use Bangsamu\Sso\Tests\TestCase;
use Bangsamu\Sso\UserMedia\MasterUserMediaResolver;
use Bangsamu\Sso\UserMedia\UserMediaCache;
use Bangsamu\Sso\UserMedia\UserMediaConflict;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Http;

/**
 * Komponen Blade (banner health, modal berdampingan, banner konflik) dan jembatan ke bangsamu/master (getSignature/getParaf).
 */
class UserMediaViewsTest extends TestCase
{
    public function test_banner_health_hanya_saat_gagal_dan_mengunci(): void
    {
        $gagal = view('sso::user-media.health-alert', ['health' => ['ok' => false, 'errors' => ['bucket mati']], 'showErrors' => true])->render();
        $this->assertStringContainsString('Server Master Data / penyimpanan gambar tidak dapat dihubungi', $gagal);
        $this->assertStringContainsString('Cek Ulang Koneksi', $gagal);
        $this->assertStringContainsString('bucket mati', $gagal);

        $this->assertStringNotContainsString('tidak dapat dihubungi', view('sso::user-media.health-alert', ['health' => ['ok' => true]])->render());
    }

    public function test_modal_berdampingan_memuat_peringatan_dan_centang(): void
    {
        $html = view('sso::user-media.compare-modal')->render();

        $this->assertStringContainsString('Di Master Data (dipakai semua aplikasi)', $html);
        $this->assertStringContainsString('gambar lama dihapus permanen', $html);
        $this->assertStringContainsString('Saya mengerti gambar lama hilang permanen', $html);
        $this->assertStringContainsString('data-um="replace" disabled', $html);
        $this->assertStringContainsString('window.SsoUserMedia', $html);
    }

    public function test_banner_konflik_untuk_pemilik_akun(): void
    {
        UserMediaConflict::query()->create(['email' => 'budi@meindo.com', 'type' => 'signature', 'found_at' => now()]);
        config(['sso_user_media.conflict_url' => 'https://spb.test/profile/media']);

        $this->actingAs(new GenericUser(['id' => 1, 'email' => 'Budi@Meindo.com']));
        $html = view('sso::user-media.conflict-banner')->render();
        $this->assertStringContainsString('Tanda tangan Anda di aplikasi ini', $html);
        $this->assertStringContainsString('https://spb.test/profile/media', $html);

        $this->actingAs(new GenericUser(['id' => 2, 'email' => 'lain@meindo.com']));
        $this->assertStringNotContainsString('berbeda dengan di Master Data', view('sso::user-media.conflict-banner')->render());
    }

    public function test_jembatan_get_signature_paket_master_membaca_cache(): void
    {
        if (! interface_exists(UserMediaResolver::class)) {
            $this->markTestSkipped('bangsamu/master terpasang belum punya Contracts\UserMediaResolver');
        }
        $png = $this->png();
        Http::fake(['master.test/api/user-media/signature*' => Http::response($png, 200, ['ETag' => '"'.hash('sha256', $png).'"'])]);

        $resolver = app(UserMediaResolver::class);
        $this->assertInstanceOf(MasterUserMediaResolver::class, $resolver);
        $this->assertSame(app(UserMediaCache::class)->filePath('signature', 'budi@meindo.com'), $resolver->localPath('signature', 'budi@meindo.com'));
    }
}
