<?php

namespace Bangsamu\Sso\Tests\Feature;

use Bangsamu\Sso\Tests\TestCase;
use Bangsamu\Sso\UserMedia\UserMediaCache;
use Bangsamu\Sso\UserMedia\UserMediaException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

/**
 * Cache lokal gambar Master Data: dipakai langsung selama 10 menit, lalu diperiksa ulang dengan If-None-Match; Master Data
 * mati = cache terakhir; tanpa cache dan Master Data mati = exception (PDF ditunda, K3).
 */
class UserMediaCacheTest extends TestCase
{
    private function cache(): UserMediaCache
    {
        return app(UserMediaCache::class);
    }

    public function test_unduh_sekali_lalu_dipakai_dari_cache_dan_diperiksa_ulang_dengan_etag(): void
    {
        $png = $this->png();
        $sha = hash('sha256', $png);
        Http::fakeSequence('master.test/api/user-media/signature*')
            ->push($png, 200, ['ETag' => '"'.$sha.'"', 'X-Pixel-Hash' => str_repeat('p', 64), 'X-Source-App' => 'APP03', 'Content-Type' => 'image/png'])
            ->push('', 304, ['ETag' => '"'.$sha.'"']);

        $path = $this->cache()->path('signature', 'Budi@Meindo.com');
        $this->assertSame($png, file_get_contents($path));
        $meta = $this->cache()->meta('signature', 'budi@meindo.com');
        $this->assertSame($sha, $meta['sha256']);
        $this->assertSame(str_repeat('p', 64), $meta['pixel_hash']);
        $this->assertSame('APP03', $meta['source_app']);

        $this->assertSame($path, $this->cache()->path('signature', 'budi@meindo.com'));
        Http::assertSentCount(1);

        $this->travel(11)->minutes();
        $this->assertSame($path, $this->cache()->path('signature', 'budi@meindo.com'));
        Http::assertSentCount(2);
        Http::assertSent(fn (Request $request) => $request->header('If-None-Match') === ['"'.$sha.'"']);
        $this->assertSame($png, file_get_contents($path));
    }

    public function test_gambar_baru_menggantikan_dan_404_menghapus_cache(): void
    {
        $lama = $this->png('merah');
        $baru = $this->png('biru');
        Http::fakeSequence('master.test/api/user-media/paraf*')
            ->push($lama, 200, ['ETag' => '"'.hash('sha256', $lama).'"'])
            ->push($baru, 200, ['ETag' => '"'.hash('sha256', $baru).'"'])
            ->push(['status' => 'gagal', 'code' => 404, 'data' => ['reason' => 'not_found']], 404);

        $path = $this->cache()->path('paraf', 'budi@meindo.com');
        $this->assertSame($baru, file_get_contents($this->cache()->path('paraf', 'budi@meindo.com', true)));
        $this->assertSame(hash('sha256', $baru), $this->cache()->status('paraf', 'budi@meindo.com')['sha256']);

        $this->assertNull($this->cache()->path('paraf', 'budi@meindo.com', true));
        $this->assertFileDoesNotExist($path);
        $this->assertFalse($this->cache()->status('paraf', 'budi@meindo.com')['exists']);
        Http::assertSentCount(3); // "tidak ada" juga di-cache, tidak bertanya lagi dalam 10 menit
    }

    public function test_master_data_mati_memakai_cache_terakhir_tanpa_cache_dilempar(): void
    {
        $png = $this->png();
        $this->cache()->remember('signature', 'budi@meindo.com', $png, ['pixel_hash' => 'x']);
        $this->travel(1)->hours();
        Http::fake(fn () => throw new ConnectionException('Connection refused'));

        $this->assertSame($png, file_get_contents($this->cache()->path('signature', 'budi@meindo.com')));

        try {
            $this->cache()->path('signature', 'orang.baru@meindo.com');
            $this->fail('tanpa cache harus dilempar');
        } catch (UserMediaException $e) {
            $this->assertTrue($e->isUnavailable(), 'PDF ditunda (K3), bukan dicetak tanpa tanda tangan');
        }
    }
}
