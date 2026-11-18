<?php

namespace Bangsamu\Sso\Tests;

use Bangsamu\Sso\SsoPackageServiceProvider;
use Bangsamu\Sso\UserMedia\UserMediaToken;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected string $privateKey;

    protected string $publicKey;

    protected string $cachePath;

    protected function getPackageProviders($app)
    {
        return [SsoPackageServiceProvider::class];
    }

    protected function defineEnvironment($app)
    {
        $pair = UserMediaToken::generateKeyPair();
        $this->privateKey = $pair['secret'];
        $this->publicKey = $pair['public'];
        $this->cachePath = sys_get_temp_dir().'/sso-user-media-test-'.getmypid().'-'.uniqid();

        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('database.default', 'testing');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('SsoConfig.main.APP_CODE', 'APP32');
        $app['config']->set('sso_user_media.url', 'https://master.test');
        $app['config']->set('sso_user_media.private_key', $this->privateKey);
        $app['config']->set('sso_user_media.cache_path', $this->cachePath);
    }

    protected function defineDatabaseMigrations()
    {
        (require __DIR__.'/../resources/migrations/2026_11_18_000001_create_user_media_conflicts_table.php')->up();
        if (! Schema::hasTable('dashboard_settings')) {
            Schema::create('dashboard_settings', function (Blueprint $table) {
                $table->id();
                $table->string('key')->unique();
                $table->text('value')->nullable();
                $table->string('group')->default('general');
                $table->string('type')->default('text');
                $table->string('label')->default('');
                $table->text('options')->nullable();
                $table->integer('order')->default(0);
                $table->timestamps();
            });
        }
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->cachePath);
        parent::tearDown();
    }

    /**
     * Klaim token request yang dikirim client, setelah tanda tangannya diverifikasi dengan kunci publik (seperti Master Data).
     *
     * @return array<string, mixed>
     */
    protected function claimsOf(Request $request): array
    {
        $token = substr((string) $request->header('Authorization')[0], strlen('Bearer '));
        $this->assertStringStartsWith(UserMediaToken::PREFIX, $token);
        [, $body, $signature] = explode('.', $token);
        $raw = base64_decode(strtr($signature, '-_', '+/'), true);
        $this->assertTrue(sodium_crypto_sign_verify_detached($raw, UserMediaToken::PREFIX.$body, base64_decode($this->publicKey)), 'tanda tangan token valid');

        return json_decode(base64_decode(strtr($body, '-_', '+/')), true);
    }

    protected function png(string $warna = 'merah'): string
    {
        $image = imagecreatetruecolor(4, 2);
        imagefill($image, 0, 0, $warna === 'merah' ? 0xFF0000 : 0x0000FF);
        ob_start();
        imagepng($image);

        return (string) ob_get_clean();
    }

    /** jawaban health Master Data */
    protected function healthOk(string $env = 'testing'): array
    {
        return ['status' => 'sukses', 'code' => 200, 'data' => ['ok' => true, 'bucket' => 'app03-test', 'env' => $env, 'app_code' => 'APP03',
            'checked_at' => now()->toIso8601String(), 'errors' => []]];
    }
}
