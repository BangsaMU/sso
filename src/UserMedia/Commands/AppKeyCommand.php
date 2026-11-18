<?php

namespace Bangsamu\Sso\UserMedia\Commands;

use Bangsamu\Sso\UserMedia\UserMediaToken;
use Illuminate\Console\Command;
use InvalidArgumentException;

/**
 * Kunci API aplikasi ini untuk Master Data (K8): pasangan Ed25519, kunci privat ke .env (MASTER_APP_PRIVATE_KEY), kunci
 * publik + fingerprint + perintah pendaftaran di Master Data dicetak. Kunci privat tidak pernah dikirim ke Master Data.
 *
 *   php artisan sso:app-key                 cetak pasangan baru (tidak menulis apa pun)
 *   php artisan sso:app-key --write         tulis kunci privat baru ke .env (menolak menimpa kecuali --force)
 *   php artisan sso:app-key --show          kunci publik + fingerprint dari MASTER_APP_PRIVATE_KEY yang terpasang
 *   php artisan sso:app-key --format=env    MASTER_APP_PRIVATE_KEY=... dan MASTER_APP_PUBLIC_KEY=... (untuk skrip)
 * Rotasi: --write --force di app, daftarkan kunci baru di Master Data, config:clear, lalu cabut kunci lama di Master Data.
 */
class AppKeyCommand extends Command
{
    protected $signature = 'sso:app-key
        {--write : tulis kunci privat baru ke .env}
        {--force : boleh menimpa MASTER_APP_PRIVATE_KEY yang sudah ada (rotasi)}
        {--show : tampilkan kunci publik dari MASTER_APP_PRIVATE_KEY yang terpasang}
        {--format=text : text atau env}
        {--env-file= : path .env (bawaan base_path(".env"))}';

    protected $description = 'Buat / tampilkan kunci API Ed25519 aplikasi ini untuk API gambar user Master Data';

    public function handle(): int
    {
        $appCode = strtoupper((string) (config('sso_user_media.app_code') ?: config('SsoConfig.main.APP_CODE') ?: 'APPXX'));

        if ($this->option('show')) {
            $secret = (string) config('sso_user_media.private_key');
            if ($secret === '') {
                $this->error('MASTER_APP_PRIVATE_KEY belum diisi. Buat dengan: php artisan sso:app-key --write');

                return self::FAILURE;
            }
            try {
                $public = UserMediaToken::publicKeyFromSecret($secret);
            } catch (InvalidArgumentException $e) {
                $this->error($e->getMessage());

                return self::FAILURE;
            }
            $this->printRegistration($appCode, $public);

            return self::SUCCESS;
        }

        $pair = UserMediaToken::generateKeyPair();

        if ($this->option('format') === 'env') {
            $this->line('MASTER_APP_PRIVATE_KEY='.$pair['secret']);
            $this->line('MASTER_APP_PUBLIC_KEY='.$pair['public']);

            return self::SUCCESS;
        }

        if ($this->option('write')) {
            $envFile = (string) ($this->option('env-file') ?: base_path('.env'));
            if (! is_file($envFile) || ! is_writable($envFile)) {
                $this->error("File {$envFile} tidak ada atau tidak bisa ditulis.");

                return self::FAILURE;
            }
            $env = (string) file_get_contents($envFile);
            $exists = preg_match('/^MASTER_APP_PRIVATE_KEY=(.*)$/m', $env, $match) === 1;
            if ($exists && trim($match[1], " \t\"'") !== '' && ! $this->option('force')) {
                $this->error('MASTER_APP_PRIVATE_KEY sudah terisi. Pakai --force untuk rotasi (kunci lama tetap terdaftar di Master Data sampai dicabut).');

                return self::FAILURE;
            }
            $line = 'MASTER_APP_PRIVATE_KEY='.$pair['secret'];
            $env = $exists
                ? preg_replace('/^MASTER_APP_PRIVATE_KEY=.*$/m', $line, $env)
                : rtrim($env, "\n")."\n\n# kunci API Ed25519 aplikasi ini untuk Master Data (rahasia, php artisan sso:app-key)\n".$line."\n";
            file_put_contents($envFile, $env);
            $this->info("Kunci privat ditulis ke {$envFile}. Jalankan php artisan config:clear (atau config:cache).");
        } else {
            $this->warn('Simpan di .env aplikasi ini (rahasia, jangan di-commit / jangan dikirim ke Master Data):');
            $this->line('MASTER_APP_PRIVATE_KEY='.$pair['secret']);
        }

        $this->newLine();
        $this->printRegistration($appCode, $pair['public']);

        return self::SUCCESS;
    }

    private function printRegistration(string $appCode, string $public): void
    {
        $this->line('Kunci publik : '.$public);
        $this->line('Fingerprint  : '.UserMediaToken::fingerprint($public));
        $this->newLine();
        $this->info('Daftarkan di Master Data (Apps → '.$appCode.' → tab Kunci API, atau di server Master Data):');
        $this->line('php artisan master:app-key --register='.$appCode.' --public='.$public
            .' --name="'.$appCode.' '.app()->environment().' '.now()->format('Y-m').'" --scope=user_media');
    }
}
