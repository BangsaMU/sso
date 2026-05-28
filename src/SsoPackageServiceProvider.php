<?php

namespace Bangsamu\Sso;

use Illuminate\Support\ServiceProvider;
use Bangsamu\Master\Models\DashboardSettings;
use Illuminate\Support\Facades\View;

class SsoPackageServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        config([
            'database.connections.db_master' => [

                'driver' => 'mysql',

                'host' => config('SsoConfig.db_master.host'),

                'port' => config('SsoConfig.db_master.port'),

                'database' => config('SsoConfig.db_master.database'),

                'username' => config('SsoConfig.db_master.username'),

                'password' => config('SsoConfig.db_master.password'),

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
