<?php

namespace Bangsamu\Sso\UserMedia;

use Bangsamu\Sso\UserMedia\Contracts\LegacyUserMediaSource;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Storage;
use Throwable;

/**
 * Sumber gambar lama bawaan `sso:user-media-sync` (dipakai bila config sso_user_media.legacy_source kosong). Membaca pola yang
 * dipakai aplikasi SSO: tabel `user_details` dengan baris per user per jenis (`field_key` signature / paraf / profile_photo,
 * `field_value` = path file). Semua bagian yang berbeda antar aplikasi diatur lewat config sso_user_media.legacy:
 *   - roots   : folder / disk tempat path dicari berurutan (absolut, relatif storage/, atau `disk:<nama>`); file pertama
 *               yang ada dipakai, jadi `/media/signature/x.png` (relatif storage/) dan `signatures/x.png` (disk media)
 *               sama-sama terbaca tanpa diatur satu per satu;
 *   - email   : kolom email di tabel itu, atau `users.email` (join lewat user_id) bila email di sana bisa usang;
 *   - pick    : baris mana yang dipakai bila satu user punya beberapa baris (latest = id terbesar, first = id terkecil);
 *   - on_synced: keep = nilai lokal tidak diubah (aplikasi tetap memakai file sendiri), ref = diganti `app03:<type>`.
 * Path yang tidak ketemu di root mana pun = "File lokal hilang" (dilewati, tidak error), dengan daftar path yang dicoba.
 */
class UserDetailsLegacySource implements LegacyUserMediaSource
{
    /**
     * @return iterable<LegacyUserMedia>
     */
    public function items(?string $type = null, ?string $email = null): iterable
    {
        $config = $this->config();
        $table = $config['table'];
        $key = $config['key_column'];
        $value = $config['value_column'];
        $userId = $config['user_id_column'];
        $joinUsers = $config['email'] === 'users.email';
        $hasUserId = $userId !== null && Schema::hasColumn($table, $userId);

        $softDelete = $this->softDeleteColumn($table);
        $chosen = DB::table($table)
            ->select(DB::raw(($config['pick'] === 'first' ? 'MIN' : 'MAX').'(id) AS id'))
            ->whereIn($key, $type !== null ? [$type] : UserMediaClient::TYPES)
            ->whereNotNull($value)
            ->where($value, '!=', '')
            ->when($softDelete !== null, fn ($query) => $query->whereNull($softDelete))
            ->groupBy($joinUsers ? $userId : $config['email'], $key);

        $rows = DB::table($table.' as ud')
            ->joinSub($chosen, 'chosen', 'chosen.id', '=', 'ud.id')
            ->when($joinUsers, fn ($query) => $query->join($config['users_table'].' as owner', 'owner.id', '=', 'ud.'.$userId))
            ->select(array_values(array_filter([
                'ud.'.$key.' as media_type',
                'ud.'.$value.' as media_value',
                $joinUsers ? 'owner.email as media_email' : 'ud.'.$config['email'].' as media_email',
                $hasUserId ? 'ud.'.$userId.' as media_user_id' : null,
            ])))
            ->when($email !== null, fn ($query) => $query->where($joinUsers ? 'owner.email' : 'ud.'.$config['email'], strtolower(trim($email))))
            ->orderBy('media_email')
            ->orderBy('media_type')
            ->cursor();

        foreach ($rows as $row) {
            $value = trim((string) $row->media_value);
            if (blank($row->media_email) || $this->isMasterRef($value)) {
                continue;
            }
            [$path, $searched] = $this->resolve($value);

            yield new LegacyUserMedia(
                strtolower(trim((string) $row->media_email)),
                (string) $row->media_type,
                $path,
                $value,
                $row->media_user_id ?? null,
                $searched,
            );
        }
    }

    /**
     * @param  array<string, mixed>  $media
     */
    public function markSynced(LegacyUserMedia $item, array $media): void
    {
        $config = $this->config();
        if ($config['on_synced'] !== 'ref') {
            return;
        }

        DB::table($config['table'])
            ->where($config['key_column'], $item->type)
            ->where($config['value_column'], $item->localRef)
            ->when($item->userId !== null && $config['user_id_column'] !== null,
                fn ($query) => $query->where($config['user_id_column'], $item->userId),
                fn ($query) => $query->where($config['email'] === 'users.email' ? $config['user_id_column'] : $config['email'], $item->email))
            ->update([$config['value_column'] => $config['ref_prefix'].$item->type]);
    }

    /**
     * Folder pencarian yang sudah diterjemahkan ke path absolut (untuk laporan / peringatan).
     *
     * @return list<string>
     */
    public function roots(): array
    {
        $roots = [];
        foreach ($this->config()['roots'] as $root) {
            $root = trim((string) $root);
            if ($root === '') {
                continue;
            }
            if (str_starts_with($root, 'disk:')) {
                try {
                    $root = Storage::disk(substr($root, 5))->path('');
                } catch (Throwable) {
                    continue;
                }
            } elseif (! str_starts_with($root, '/')) {
                $root = $root === '.' ? storage_path() : storage_path($root);
            }
            $roots[] = rtrim($root, '/');
        }

        return array_values(array_unique($roots));
    }

    /**
     * @return array{0: ?string, 1: list<string>}
     */
    private function resolve(string $value): array
    {
        if ($value === '' || str_contains($value, '..') || str_starts_with($value, 'data:') || filter_var($value, FILTER_VALIDATE_URL) !== false) {
            return [null, []];
        }

        $searched = [];
        foreach ($this->roots() as $root) {
            $candidate = $root.'/'.ltrim($value, '/');
            $searched[] = $candidate;
            if (is_file($candidate)) {
                return [$candidate, $searched];
            }
        }

        return [null, $searched];
    }

    private function isMasterRef(string $value): bool
    {
        return preg_match('/^app03[a-z0-9-]*:/i', $value) === 1;
    }

    private function softDeleteColumn(string $table): ?string
    {
        $column = $this->config()['soft_delete_column'];

        return $column !== null && Schema::hasColumn($table, $column) ? $column : null;
    }

    /**
     * @return array{table: string, key_column: string, value_column: string, email: string, user_id_column: ?string,
     *     users_table: string, soft_delete_column: ?string, pick: string, roots: list<string>, on_synced: string, ref_prefix: string}
     */
    private function config(): array
    {
        $config = (array) config('sso_user_media.legacy', []);
        $roots = $config['roots'] ?? null;

        return [
            'table' => (string) ($config['table'] ?? 'user_details'),
            'key_column' => (string) ($config['key_column'] ?? 'field_key'),
            'value_column' => (string) ($config['value_column'] ?? 'field_value'),
            'email' => (string) ($config['email'] ?? 'user_email'),
            'user_id_column' => isset($config['user_id_column']) ? (string) $config['user_id_column'] : 'user_id',
            'users_table' => (string) ($config['users_table'] ?? 'users'),
            'soft_delete_column' => array_key_exists('soft_delete_column', $config) ? $config['soft_delete_column'] : 'deleted_at',
            'pick' => ($config['pick'] ?? 'latest') === 'first' ? 'first' : 'latest',
            'roots' => is_string($roots) ? explode(',', $roots) : (array) ($roots ?? ['.', 'media', 'app', 'app/public', 'disk:media', 'disk:public']),
            'on_synced' => ($config['on_synced'] ?? 'keep') === 'ref' ? 'ref' : 'keep',
            'ref_prefix' => (string) ($config['ref_prefix'] ?? 'app03:'),
        ];
    }
}
