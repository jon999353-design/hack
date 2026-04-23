// VendorGuard AI — runtime frontend config.
//
// The single source of truth for the backend API URL. Resolution order:
//   1. A ?api=... query string (easiest for demo day — no redeploy needed).
//   2. localStorage['VG_API'] (sticky between reloads on the same browser).
//   3. A <meta name="vg-api" content="..."> tag in index.html.
//   4. window.__VG_API_FALLBACK__ set below (edit this before committing
//      a production build, or leave blank to default to localhost).
//
// Set it from the URL for a one-off live demo:
//   https://vendorguard.vercel.app/?api=https://vendorguard-api.up.railway.app
//
// Or persist it in this browser for the whole event:
//   localStorage.setItem('VG_API', 'https://vendorguard-api.up.railway.app')
(function () {
  const qs = new URLSearchParams(window.location.search);
  const fromQuery = qs.get('api');
  if (fromQuery) {
    try { localStorage.setItem('VG_API', fromQuery); } catch (e) { /* private mode */ }
  }

  const fromStorage = (function () {
    try { return localStorage.getItem('VG_API'); } catch (e) { return null; }
  })();

  const metaEl = document.querySelector('meta[name="vg-api"]');
  const fromMeta = metaEl ? metaEl.getAttribute('content') : null;

  // EDIT ME FOR YOUR PRODUCTION DEPLOY (or leave blank to keep localhost default):
  window.__VG_API_FALLBACK__ = window.__VG_API_FALLBACK__ || '';

  const candidates = [
    fromQuery,
    fromStorage,
    fromMeta && metaEl && !metaEl.getAttribute('content').includes('__VG_API__') ? fromMeta : null,
    window.__VG_API_FALLBACK__,
  ];
  const picked = candidates.find((v) => v && !v.includes('__VG_API__')) || 'http://127.0.0.1:8765';
  window.VG_API = picked.replace(/\/+$/, '');
})();
