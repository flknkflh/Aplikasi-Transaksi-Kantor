package api

import "net/http"

// VerifyRoutes is a stripped-down handler that exposes ONLY public
// verification: a browser upload page, the verify API, the QR landing page,
// and the public CA material. No auth, no registration, no signing, no admin.
// Run it on its own port (PQC_VERIFY_ADDR) so a verification-only service can
// be published separately from the signing API.
func (s *Server) VerifyRoutes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.hVerifyHome)
	mux.HandleFunc("POST /api/v1/verify", s.limit(s.rlVerify, byIP, s.hPublicVerify))
	mux.HandleFunc("GET /s/{public_id}", s.hScanResolver)
	mux.HandleFunc("GET /v/{public_id}", s.hVerifyPage)
	mux.HandleFunc("GET /v/{public_id}/document", s.hPublicDocument)
	mux.HandleFunc("GET /api/v1/public/signatures/{public_id}", s.hPublicRecord)
	mux.HandleFunc("GET /api/v1/public/ca/root.crt", s.pem(func() []byte { return s.cfg.RootCAPEM }))
	mux.HandleFunc("GET /api/v1/public/ca/chain.pem", s.pem(func() []byte { return s.cfg.CAChainPEM }))
	mux.HandleFunc("GET /api/v1/public/ca/crl.pem", s.pem(func() []byte { return s.crl }))

	s.mountUIKit(mux)

	// The verify page may be opened at one address (localhost) while pointed
	// at the server on another (the LAN IP typed into the "Alamat server"
	// box). This service is public and read-only, so allow any origin.
	return corsAny(mux)
}

func corsAny(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hVerifyHome serves the upload page for the standalone verification service.
// After a successful check it also shows the "scan" view: the server record
// and the authoritative signed PDF, exactly like opening the QR link.
func (s *Server) hVerifyHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	body := serverBar(reqBase(r)) + verifyHomeBody
	_, _ = w.Write([]byte(verifyPageShell("Verifikasi Dokumen", body)))
}

const verifyHomeBody = `
<p class="muted" style="margin-top:0">Unggah berkas PDF bertanda tangan untuk memeriksa keaslian &amp;
keutuhannya. Tidak perlu akun. Berkas Anda diperiksa di server lalu dibuang — tidak disimpan.</p>

<h2>Unggah berkas PDF</h2>
<label id="drop" for="file">
  <input id="file" type="file" accept="application/pdf" style="display:none">
  <svg class="dz-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4m0 0 4 4m-4-4-4 4"/><path d="M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/></svg>
  <span id="dz">Seret &amp; lepas berkas PDF di sini</span>
  <span class="muted" style="display:block;margin-top:8px">atau</span>
  <span class="btn btn-primary" style="margin-top:10px" data-no-ripple>Pilih Berkas PDF</span>
  <span class="muted" style="display:block;margin-top:10px">Hanya berkas PDF · ukuran maksimal 50 MB</span>
</label>

<div id="out" style="margin-top:16px"></div>

<div class="v-feat">
  <div class="f"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg><div><b>Aman &amp; Privat</b><span>Berkas tidak disimpan di server</span></div></div>
  <div class="f"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/></svg><div><b>Standar Post-Quantum</b><span>ML-DSA-65 (FIPS 204)</span></div></div>
  <div class="f"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m9 11 3 3 8-8"/><path d="M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h11"/></svg><div><b>Mudah Digunakan</b><span>Tanpa akun, langsung verifikasi</span></div></div>
</div>

<script>
(function(){
  var file = document.getElementById('file'),
      drop = document.getElementById('drop'),
      dz   = document.getElementById('dz'),
      out  = document.getElementById('out');

  ['dragenter','dragover'].forEach(function(ev){
    drop.addEventListener(ev, function(e){ e.preventDefault(); drop.classList.add('drag'); });
  });
  ['dragleave','drop'].forEach(function(ev){
    drop.addEventListener(ev, function(e){ e.preventDefault(); drop.classList.remove('drag'); });
  });
  drop.addEventListener('drop', function(e){
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) run(e.dataTransfer.files[0]);
  });
  file.addEventListener('change', function(){ if (file.files[0]) run(file.files[0]); });

  function esc(s){ return String(s == null ? '' : s).replace(/[&<>]/g, function(c){
    return ({'&':'&amp;','<':'&lt;','>':'&gt;'})[c]; }); }
  function row(k,v){ return v ? '<tr><th>'+esc(k)+'</th><td>'+esc(v)+'</td></tr>' : ''; }

  function run(f){
    dz.textContent = f.name;
    out.innerHTML = '<p class="muted">Memeriksa…</p>';
    var fd = new FormData(); fd.append('file', f);
    fetch(window.SRV + '/api/v1/verify', { method:'POST', body: fd })
      .then(function(r){ return r.json().then(function(j){ return { ok:r.ok, j:j }; }); })
      .then(function(res){
        if (!res.ok) { out.innerHTML = '<p class="bad">'+esc(res.j && res.j.error || 'Gagal memeriksa berkas.')+'</p>'; return; }
        render(res.j);
      })
      .catch(function(e){ out.innerHTML = '<p class="bad">Gagal menghubungi server verifikasi di '+esc(window.SRV)+'. Periksa alamat server di atas.</p>'; });
  }

  function humanCert(s){
    return ({revoked:'DICABUT', device_reported_lost:'perangkat dilaporkan hilang',
             not_server_verified:'tidak diverifikasi otomatis oleh server', active:'aktif'})[s] || s; }

  function render(top){
    var o = top.verification || top;
    var sigs = o.signatures || [];
    var rec = top.record || {};
    var storedOnly = rec.verification_status === 'stored_unverified' || rec.certificate_status === 'not_server_verified';
    var storedNote = storedOnly
      ? '<p class="muted">⚠ Berkas ini terlalu besar untuk diverifikasi otomatis oleh server saat diunggah — server hanya menyimpan salinan &amp; mencatat SHA-512-nya. Kecocokan kriptografis di atas dihitung sekarang dari berkas yang Anda unggah.</p>'
      : '';
    if (o.valid && sigs.length){
      var s = sigs[0];
      var subj = s.subject || '';
      var name = (subj.match(/CN=([^,]+)/) || [,'-'])[1];
      var org  = (subj.match(/O=([^,]+)/)  || [,'-'])[1];
      var pid  = rec.public_id || String(s.contact || '').replace('pqc-public-id:', '');
      var docv = '';
      if (top.registered === true && pid){
        var docURL = window.SRV + '/v/' + encodeURIComponent(pid) + '/document';
        var pageURL = window.SRV + '/v/' + encodeURIComponent(pid);
        docv =
          '<div class="doc"><h2>Dokumen yang ditandatangani</h2>' +
          '<p class="muted">Berkas asli yang tersimpan di server. Bandingkan dengan yang Anda terima.</p>' +
          '<iframe src="'+esc(docURL)+'" title="Dokumen bertanda tangan"></iframe>' +
          '<div class="docbtns">' +
          '<a class="btn" href="'+esc(docURL)+'" target="_blank" rel="noopener">Buka layar penuh / unduh (PDF)</a>' +
          '<a class="btn alt" href="'+esc(pageURL)+'" target="_blank" rel="noopener">Halaman verifikasi lengkap</a>' +
          '</div></div>';
      }
      out.innerHTML =
        '<div class="status"><span class="badge ok">TANDA TANGAN SAH</span></div>' +
        '<table>' +
          row('Penanda tangan', name) +
          row('Instansi', org) +
          row('Algoritma', s.algorithm) +
          row('Alasan', s.reason) +
          row('Waktu (klaim perangkat)', s.client_claimed_signing_time) +
          row('No. sertifikat', s.certificate_serial) +
          row('Sidik jari sertifikat', rec.certificate_fingerprint) +
          row('Perangkat', rec.device_label) +
          row('Status sertifikat', rec.certificate_status ? humanCert(rec.certificate_status) : '') +
          row('Rantai tepercaya', s.trusted_chain ? 'ya' : 'TIDAK') +
          row('Sertifikat dicabut', s.revoked ? 'YA' : 'tidak') +
          row('Terdaftar di server', top.registered === true ? (storedOnly ? 'ya (disimpan, tidak diverifikasi otomatis)' : 'ya') : 'tidak') +
          row('ID verifikasi', pid) +
        '</table>' + docv + storedNote +
        '<p class="muted">Waktu di atas berasal dari jam perangkat penandatangan, bukan stempel waktu tepercaya.</p>';
    } else {
      var errs = o.errors || (sigs[0] && sigs[0].errors) || [];
      out.innerHTML =
        '<div class="status"><span class="badge bad">TIDAK SAH</span></div>' +
        (errs.length ? '<ul class="muted">' + errs.map(function(x){ return '<li>'+esc(x)+'</li>'; }).join('') + '</ul>'
                     : '<p class="muted">Dokumen tidak memuat tanda tangan ML-DSA-65 yang valid.</p>');
    }
  }
})();
</script>`
