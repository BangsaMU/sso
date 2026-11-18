<?php

namespace Bangsamu\Sso\Tests\Feature;

use Bangsamu\Sso\Tests\TestCase;
use Bangsamu\Sso\UserMedia\UserMediaClient;
use Bangsamu\Sso\UserMedia\UserMediaException;
use Bangsamu\Sso\UserMedia\UserMediaToken;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

/**
 * Client API gambar user: format token sama dengan verifier Master Data, isi request (multipart / JSON / query), alasan
 * penolakan diteruskan, health di-cache, dan penjaga dev → Master Data produksi.
 */
class UserMediaClientTest extends TestCase
{
    private function client(): UserMediaClient
    {
        return app(UserMediaClient::class);
    }

    public function test_token_ditandatangani_kunci_privat_dan_terikat_ke_request(): void
    {
        $claims = UserMediaToken::claims('app32', 'post', '/api/user-media/signature/check', str_repeat('A', 64), ' Budi@Meindo.com ', 'admin@meindo.com', 999, 'abc');
        $this->assertSame(1, $claims['v']);
        $this->assertSame('APP32', $claims['iss']);
        $this->assertSame('user-media', $claims['aud']);
        $this->assertSame(60, $claims['exp'] - $claims['iat'], 'umur dibatasi 60 detik');
        $this->assertSame('POST', $claims['htm']);
        $this->assertSame('api/user-media/signature/check', $claims['htu']);
        $this->assertSame(str_repeat('a', 64), $claims['bsh']);
        $this->assertSame('budi@meindo.com', $claims['sub']);
        $this->assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $claims['jti']);

        $token = UserMediaToken::sign($this->privateKey, $claims);
        [$prefix, $body, $signature] = explode('.', $token);
        $this->assertSame('umt1', $prefix);
        $this->assertTrue(sodium_crypto_sign_verify_detached(base64_decode(strtr($signature, '-_', '+/')), 'umt1.'.$body, base64_decode($this->publicKey)));
        $this->assertSame($this->publicKey, UserMediaToken::publicKeyFromSecret($this->privateKey));
        $this->assertSame(substr(hash('sha256', base64_decode($this->publicKey)), 0, 16), UserMediaToken::fingerprint($this->publicKey));
    }

    public function test_health_di_cache_dan_jawaban_503_master_data_jadi_tidak_ok(): void
    {
        Http::fake(['master.test/api/user-media/health' => Http::response(['status' => 'gagal', 'code' => 503,
            'data' => ['ok' => false, 'bucket' => 'app03', 'env' => 'testing', 'errors' => ['bucket produksi ditolak']]], 503)]);

        $health = $this->client()->health();
        $this->assertFalse($health['ok']);
        $this->assertTrue($health['reachable']);
        $this->assertSame(['bucket produksi ditolak'], $health['errors']);
        $this->client()->health();
        Http::assertSentCount(1);

        Http::assertSent(function (Request $request) {
            $claims = $this->claimsOf($request);

            return $request->method() === 'GET' && $claims['htu'] === 'api/user-media/health' && $claims['bsh'] === hash('sha256', '')
                && ! isset($claims['sub']) && $claims['kid'] === UserMediaToken::fingerprint($this->publicKey);
        });
    }

    public function test_master_data_tidak_terjangkau_health_gagal_dan_upload_dikunci(): void
    {
        Http::fake(fn () => throw new ConnectionException('Connection refused'));

        $health = $this->client()->health();
        $this->assertFalse($health['ok']);
        $this->assertFalse($health['reachable']);
        $this->assertStringContainsString('tidak dapat dihubungi', $health['errors'][0]);

        try {
            $this->client()->check('signature', 'budi@meindo.com', 'budi@meindo.com', $this->png());
            $this->fail('upload harus dikunci');
        } catch (UserMediaException $e) {
            $this->assertSame('unhealthy', $e->reason);
            $this->assertTrue($e->isUnavailable());
        }
    }

    public function test_check_multipart_dengan_hash_file_dan_klaim_pemilik_pelaku(): void
    {
        $png = $this->png();
        Http::fake([
            'master.test/api/user-media/health' => Http::response($this->healthOk()),
            'master.test/api/user-media/signature/check' => Http::response(['status' => 'sukses', 'code' => 200, 'data' => [
                'master_exists' => false, 'same' => false, 'requires_confirmation' => false, 'check_token' => 'tok-1',
                'candidate' => ['pixel_hash' => str_repeat('b', 64), 'preview' => 'data:image/png;base64,AA=='], 'master' => ['exists' => false]]]),
        ]);

        $data = $this->client()->check('signature', 'Budi@Meindo.com', 'Admin@Meindo.com', $png, 'ttd.png');
        $this->assertSame('tok-1', $data['check_token']);

        Http::assertSent(function (Request $request) use ($png) {
            if (! str_ends_with($request->url(), '/signature/check')) {
                return false;
            }
            $claims = $this->claimsOf($request);
            $parts = collect($request->data())->keyBy('name');

            return $request->isMultipart() && $claims['htm'] === 'POST' && $claims['htu'] === 'api/user-media/signature/check'
                && $claims['bsh'] === hash('sha256', $png) && $claims['sub'] === 'budi@meindo.com' && $claims['act'] === 'admin@meindo.com'
                && $parts['file']['contents'] === $png && $parts['email']['contents'] === 'budi@meindo.com';
        });
    }

    public function test_commit_json_dan_409_diteruskan_dengan_alasan_dan_status_master(): void
    {
        Http::fake([
            'master.test/api/user-media/health' => Http::response($this->healthOk()),
            'master.test/api/user-media/paraf/commit' => Http::response(['status' => 'gagal', 'code' => 409, 'data' => [
                'reason' => 'replace_requires_confirmation', 'message' => 'Gambar di Master Data berbeda.', 'master' => ['sha256' => 'abc']]], 409),
        ]);

        try {
            $this->client()->commit('paraf', 'budi@meindo.com', 'budi@meindo.com', 'tok-1', false);
            $this->fail('409 harus dilempar');
        } catch (UserMediaException $e) {
            $this->assertSame('replace_requires_confirmation', $e->reason);
            $this->assertSame(409, $e->status);
            $this->assertSame('abc', $e->data['master']['sha256']);
            $this->assertFalse($e->isUnavailable());
        }

        Http::assertSent(function (Request $request) {
            if (! str_ends_with($request->url(), '/paraf/commit')) {
                return false;
            }
            $claims = $this->claimsOf($request);

            return $claims['bsh'] === hash('sha256', $request->body())
                && json_decode($request->body(), true) === ['email' => 'budi@meindo.com', 'check_token' => 'tok-1', 'confirm_replace' => false];
        });
    }

    public function test_hapus_lewat_query_dan_status(): void
    {
        Http::fake([
            'master.test/api/user-media/health' => Http::response($this->healthOk()),
            'master.test/api/user-media/profile_photo*' => Http::response(['status' => 'sukses', 'code' => 200, 'data' => ['result' => 'deleted']]),
            'master.test/api/user-media/status*' => Http::response(['status' => 'sukses', 'code' => 200, 'data' => ['email' => 'budi@meindo.com',
                'media' => ['signature' => ['exists' => true], 'paraf' => ['exists' => false], 'profile_photo' => ['exists' => false]]]]),
        ]);

        $this->assertSame('deleted', $this->client()->delete('profile_photo', 'budi@meindo.com', 'admin@meindo.com')['result']);
        $this->assertTrue($this->client()->status('BUDI@meindo.com')['signature']['exists']);

        Http::assertSent(function (Request $request) {
            if ($request->method() !== 'DELETE') {
                return false;
            }
            $claims = $this->claimsOf($request);

            return str_contains($request->url(), 'confirm_delete=true') && str_contains($request->url(), 'email=budi%40meindo.com')
                && $claims['bsh'] === hash('sha256', '') && $claims['htu'] === 'api/user-media/profile_photo';
        });
    }

    public function test_dev_tidak_boleh_menulis_ke_master_data_produksi(): void
    {
        Http::fake(['master.test/api/user-media/health' => Http::response($this->healthOk('production'))]);

        try {
            $this->client()->check('signature', 'budi@meindo.com', 'budi@meindo.com', $this->png());
            $this->fail('harus ditolak');
        } catch (UserMediaException $e) {
            $this->assertSame('dev_to_production_blocked', $e->reason);
        }
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), '/check'));
    }

    public function test_belum_dikonfigurasi(): void
    {
        config(['sso_user_media.private_key' => null]);
        Http::fake();

        $this->assertFalse($this->client()->configured());
        $this->assertFalse($this->client()->health()['ok']);
        $this->expectException(UserMediaException::class);
        $this->client()->check('signature', 'budi@meindo.com', 'budi@meindo.com', $this->png());
    }
}
