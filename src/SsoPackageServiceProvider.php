<?php

namespace Bangsamu\Sso;

use Bangsamu\Master\Models\DashboardSettings;
use Bangsamu\Sso\UserMedia\Commands\AppKeyCommand;
use Bangsamu\Sso\UserMedia\Commands\UserMediaSyncCommand;
use Bangsamu\Sso\UserMedia\MasterUserMediaResolver;
use Bangsamu\Sso\UserMedia\UserMediaCache;
use Bangsamu\Sso\UserMedia\UserMediaClient;
use Illuminate\Support\Facades\View;
use Illuminate\Support\ServiceProvider;

class SsoPackageServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // gambar user Master Data (signature, paraf, foto profil): client API + cache lokal, config('sso_user_media.*')
        $this->mergeConfigFrom(__DIR__.'/../resources/config/user_media.php', 'sso_user_media');
        $this->app->singleton(UserMediaClient::class);
        $this->app->singleton(UserMediaCache::class);
        // api/getSignature + api/getParaf paket bangsamu/master membaca rujukan "app03:" lewat cache ini (bila master mendukung)
        if (interface_exists(\Bangsamu\Master\Contracts\UserMediaResolver::class)) {
            $this->app->singleton(\Bangsamu\Master\Contracts\UserMediaResolver::class, MasterUserMediaResolver::class);
        }

        config([
            'database.connections.db_master' => [

                'driver' => 'mysql',

                'host'     => config('database.connections.db_master.host') ?? config('ssoconfig.db_master.host'),
                'port'     => config('database.connections.db_master.port') ?? config('ssoconfig.db_master.port'),
                'database' => config('database.connections.db_master.database') ?? config('ssoconfig.db_master.database'),
                'username' => config('database.connections.db_master.username') ?? config('ssoconfig.db_master.username'),
                'password' => config('database.connections.db_master.password') ?? config('ssoconfig.db_master.password'),

                'charset' => 'utf8mb4',

                'collation' => 'utf8mb4_unicode_ci',

                'prefix' => '',

                'strict' => true,

                'engine' => null,
            ]
        ]);
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        //
        $this->loadRoutesFrom(__DIR__.'/routes.php');
        $this->publishes([
            __DIR__.'/../resources/config/SsoConfig.php' => config_path('SsoConfig.php'),
        ], 'sso-config'); // <--- Tambahkan tag 'sso-config' di sini
        // php artisan vendor:publish --tag=sso-config

        // =========================================================================
        // TAMBAHKAN INI: Publish Assets (CSS & JS Tabler)
        // Diasumsikan file asli ada di folder package Anda: /resources/assets/css/ dst.
        // =========================================================================
        $this->publishes([
            __DIR__.'/../resources/assets/css/tabler.min.css' => public_path('tabler.min.css'),
            __DIR__.'/../resources/assets/js/tabler.min.js'   => public_path('tabler.min.js'),
        ], 'sso-assets');
        // php artisan vendor:publish --tag=sso-assets


        $this->loadViewsFrom(__DIR__.'/../resources/views', 'sso');

        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/sso'),
        ]);

        // $this->publishes([
        //     __DIR__.'/../resources/views/' => resource_path('views/adminlte/auth/login.blade.php'),
        // ]);

        $this->publishes([
            __DIR__.'/routes.php' => base_path('routes/sso.php'),
        ]);

        // gambar user Master Data: config, tabel konflik lokal, perintah kunci API + sinkron data lama
        $this->publishes([
            __DIR__.'/../resources/config/user_media.php' => config_path('sso_user_media.php'),
        ], 'sso-user-media');
        $this->publishes([
            __DIR__.'/../resources/migrations/2026_11_18_000001_create_user_media_conflicts_table.php' => database_path('migrations/2026_11_18_000001_create_user_media_conflicts_table.php'),
        ], 'sso-user-media-migrations');
        if ($this->app->runningInConsole()) {
            $this->commands([AppKeyCommand::class, UserMediaSyncCommand::class]);
        }

        // Tambahkan \Illuminate\Support\Facades\ di depan View
        View::composer('*', function ($view) {
            // PERBAIKAN: Kita simpan ke cache dalam bentuk ARRAY murni, bukan objek Collection
            $settingsArray = cache()->remember('appearance_settings_array', 3600, function () {
                return DashboardSettings::where('group', 'appearance')
                    ->get(['key', 'value']) // Ambil kolom yang dibutuhkan saja
                    ->pluck('value', 'key')  // Langsung ubah jadi ['key' => 'value']
                    ->toArray();            // Konversi ke array murni PHP
            });

            // Kita bungkus array tadi ke dalam objek anonim agar method ->get() di Blade tidak patah
            $settings = new class($settingsArray) {
                private $items;

                public function __construct(array $items) {
                    $this->items = $items;
                }

                public function get($key, $default = null) {
                    // Karena ini array murni, kita pakai array_key_exists atau null coalescing
                    return $this->items[$key] ?? $default;
                }
            };

            // Kirim objek $settings ke Blade
            $view->with('settings', $settings);
        });

    }
}
