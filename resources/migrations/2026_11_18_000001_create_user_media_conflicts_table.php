<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Konflik gambar user lokal vs Master Data (paket bangsamu/sso, sso:user-media-sync). Tabel di DB aplikasi, bukan db_master.
 * Publish: php artisan vendor:publish --tag=sso-user-media-migrations
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('user_media_conflicts')) {
            return;
        }
        Schema::create('user_media_conflicts', function (Blueprint $table) {
            $table->id();
            $table->string('email', 191);
            $table->string('type', 20)->comment('signature|paraf|profile_photo');
            $table->string('local_ref')->nullable()->comment('rujukan lokal lama, mis. nilai user_details');
            $table->string('local_path')->nullable();
            $table->char('local_pixel_hash', 64)->nullable()->comment('hash piksel file lokal menurut normalisasi Master Data');
            $table->char('master_pixel_hash', 64)->nullable();
            $table->char('master_sha256', 64)->nullable();
            $table->timestamp('found_at')->nullable();
            $table->timestamp('resolved_at')->nullable();
            $table->string('choice', 10)->nullable()->comment('master|local');
            $table->string('resolved_by', 191)->nullable();
            $table->timestamps();

            $table->index(['email', 'type']);
            $table->index('resolved_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_media_conflicts');
    }
};
