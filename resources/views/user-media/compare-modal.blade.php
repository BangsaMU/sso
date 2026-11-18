{{--
    Modal berdampingan "gambar berbeda dengan di Master Data" (paket bangsamu/sso), Bootstrap 4 atau 5. Sertakan sekali:
      @include('sso::user-media.compare-modal')
    Lalu dari JS halaman, dengan data hasil UserMediaClient::check() (requires_confirmation = true):
      SsoUserMedia.compare(data, {
          label: 'Signature',
          onReplace: function () { ...commit dengan confirm_replace=true... },  // hanya setelah centang
          onKeep: function () { ...tetap pakai gambar Master Data... },
      });
    Mode konflik sinkron (gambar lama aplikasi vs Master Data): SsoUserMedia.compare(data, {mode: 'conflict', ...}), kiri
    "Di aplikasi ini", tombol "Pakai yang di aplikasi ini" (= ganti Master Data, centang wajib) / "Pakai yang di Master Data".
--}}
<div class="modal fade" id="ssoUmCompareModal" tabindex="-1" aria-labelledby="ssoUmCompareTitle" aria-hidden="true"
    data-backdrop="static" data-bs-backdrop="static">
    <div class="modal-dialog modal-dialog-centered modal-xl">
        <div class="modal-content">
            <div class="modal-header" style="background:#ffc107;">
                <h5 class="modal-title" id="ssoUmCompareTitle">
                    <i class="fas fa-exclamation-triangle"></i> <span data-um="label">Gambar</span> <span data-um="title">berbeda dengan yang di Master Data</span>
                </h5>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <div class="font-weight-bold fw-bold mb-2" data-um="left-title">Di Master Data (dipakai semua aplikasi)</div>
                        <div class="sso-um-preview border rounded mb-2"><img data-um="left-img" src="" alt=""></div>
                        <div class="small text-muted" data-um="left-meta"></div>
                    </div>
                    <div class="col-md-6 mb-3">
                        <div class="font-weight-bold fw-bold mb-2" data-um="right-title">Gambar baru</div>
                        <div class="sso-um-preview border rounded mb-2"><img data-um="right-img" src="" alt=""></div>
                        <div class="small text-muted" data-um="right-meta"></div>
                    </div>
                </div>
                <div class="alert alert-warning mb-2">
                    Gambar ini dipakai semua aplikasi yang login lewat SSO (SPB, GDA, &hellip;). Mengganti berarti semua aplikasi ikut berubah,
                    dan gambar lama dihapus permanen, tidak bisa dikembalikan.
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="ssoUmCompareAgree">
                    <label class="form-check-label font-weight-bold fw-bold" for="ssoUmCompareAgree">Saya mengerti gambar lama hilang permanen</label>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-um="cancel">Batal</button>
                <button type="button" class="btn btn-outline-primary" data-um="keep">Tetap pakai yang di Master Data</button>
                <button type="button" class="btn btn-danger" data-um="replace" disabled>Ganti di semua aplikasi</button>
            </div>
        </div>
    </div>
</div>
<style>
    .sso-um-preview { display:flex; align-items:center; justify-content:center; min-height:160px; padding:.5rem;
        background-color:#fff; background-size:16px 16px; background-position:0 0, 0 8px, 8px -8px, -8px 0;
        background-image:linear-gradient(45deg,#e9ecef 25%,transparent 25%),linear-gradient(-45deg,#e9ecef 25%,transparent 25%),
            linear-gradient(45deg,transparent 75%,#e9ecef 75%),linear-gradient(-45deg,transparent 75%,#e9ecef 75%); }
    .sso-um-preview img { max-width:100%; max-height:240px; object-fit:contain; }
</style>
<script>
    window.SsoUserMedia = window.SsoUserMedia || (function () {
        var el = document.getElementById('ssoUmCompareModal');
        var q = function (name) { return el.querySelector('[data-um="' + name + '"]'); };
        var agree = document.getElementById('ssoUmCompareAgree');
        var handlers = {};

        function toggle(show) {
            if (window.bootstrap && window.bootstrap.Modal) {
                var modal = window.bootstrap.Modal.getOrCreateInstance(el);
                show ? modal.show() : modal.hide();
            } else if (window.jQuery && window.jQuery.fn.modal) {
                window.jQuery(el).modal(show ? 'show' : 'hide');
            } else {
                el.style.display = show ? 'block' : 'none';
                el.classList.toggle('show', show);
            }
        }

        function meta(d) {
            if (!d) { return ''; }
            return [d.width && d.height ? d.width + '×' + d.height + ' px' : null, d.bytes ? (d.bytes / 1024).toFixed(1) + ' KB' : null,
                d.uploaded_at ? 'diunggah ' + new Date(d.uploaded_at).toLocaleString('id-ID') : null,
                d.source_app ? 'dari ' + d.source_app : null, d.uploaded_by_email ? 'oleh ' + d.uploaded_by_email : null]
                .filter(Boolean).join(' · ');
        }

        function setImage(img, src) {
            img.src = src || '';
            img.style.display = src ? '' : 'none';
        }

        agree.addEventListener('change', function () { q('replace').disabled = !agree.checked; });
        q('replace').addEventListener('click', function () {
            if (!agree.checked) { return; }
            toggle(false);
            handlers.onReplace && handlers.onReplace();
        });
        q('keep').addEventListener('click', function () { toggle(false); handlers.onKeep && handlers.onKeep(); });
        q('cancel').addEventListener('click', function () { toggle(false); handlers.onCancel && handlers.onCancel(); });

        return {
            /**
             * data = jawaban check (master, candidate). opts: label, mode ('upload'|'conflict'), localPreview + localMeta
             * (mode conflict), onReplace, onKeep, onCancel.
             */
            compare: function (data, opts) {
                opts = opts || {};
                handlers = opts;
                var conflict = opts.mode === 'conflict';
                var master = (data && data.master) || {};
                var candidate = (data && data.candidate) || {};
                q('label').textContent = opts.label || 'Gambar';
                q('title').textContent = conflict ? 'di aplikasi ini berbeda dengan di Master Data' : 'berbeda dengan yang di Master Data';
                q('left-title').textContent = conflict ? 'Di aplikasi ini' : 'Di Master Data (dipakai semua aplikasi)';
                q('right-title').textContent = conflict ? 'Di Master Data (dipakai semua aplikasi)' : 'Gambar baru';
                setImage(q('left-img'), conflict ? (opts.localPreview || candidate.preview) : master.preview);
                setImage(q('right-img'), conflict ? master.preview : candidate.preview);
                q('left-meta').textContent = conflict ? (opts.localMeta || meta(candidate)) : (master.preview ? '' : 'File di Master Data tidak terbaca. ') + meta(master);
                q('right-meta').textContent = conflict ? meta(master) : meta(candidate);
                q('keep').textContent = 'Tetap pakai yang di Master Data';
                q('replace').textContent = conflict ? 'Pakai yang di aplikasi ini (ganti di semua aplikasi)' : 'Ganti di semua aplikasi';
                agree.checked = false;
                q('replace').disabled = true;
                toggle(true);
            },
            hide: function () { toggle(false); },
        };
    })();
</script>
