<?php

namespace Bangsamu\Sso\UserMedia;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Konflik gambar lama aplikasi ini vs Master Data (gambar berbeda, sinkron tidak menimpa). Tabel lokal di aplikasi pemilik
 * file lama (migration: php artisan vendor:publish --tag=sso-user-media-migrations). Selama belum dipilih pemilik akun,
 * aplikasi tetap memakai gambar lokal (K4). choice: master | local.
 */
class UserMediaConflict extends Model
{
    protected $table = 'user_media_conflicts';

    protected $guarded = [];

    protected $casts = [
        'found_at' => 'datetime',
        'resolved_at' => 'datetime',
    ];

    public function scopeOpen(Builder $query): Builder
    {
        return $query->whereNull('resolved_at');
    }

    public function scopeForEmail(Builder $query, string $email): Builder
    {
        return $query->where('email', strtolower(trim($email)));
    }

    public function resolve(string $choice, ?string $by = null): void
    {
        $this->forceFill(['choice' => $choice, 'resolved_at' => now(), 'resolved_by' => $by])->save();
    }
}
