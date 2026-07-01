/**
 * Admin panel route'ları.
 *
 * GET  /admin/login  → Login formu
 * POST /admin/login  → Login işlemi
 * GET  /admin        → Son taramalar tablosu (oturum gerekli)
 * GET  /admin/logout → Oturumu kapat
 *
 * Kimlik bilgileri .env üzerinden okunur:
 *   ADMIN_USERNAME, ADMIN_PASSWORD
 */

const express = require('express');
const { getRecentScans } = require('../db/database');

const router = express.Router();

/* ------------------------------------------------------------------ */
/* Yardımcı: Oturum kontrolü middleware                                */
/* ------------------------------------------------------------------ */

function requireAuth(req, res, next) {
  if (req.session?.isAdmin) return next();
  res.redirect('/admin/login');
}

/* ------------------------------------------------------------------ */
/* Yardımcı: Risk seviyesine göre CSS sınıfı                          */
/* ------------------------------------------------------------------ */

function riskClass(level) {
  const map = { clean: 'clean', low: 'low', medium: 'medium', high: 'high' };
  return map[level] || 'unknown';
}

/* ------------------------------------------------------------------ */
/* Yardımcı: Tarih formatlama                                          */
/* ------------------------------------------------------------------ */

function fmtDate(raw) {
  if (!raw) return '—';
  try {
    return new Date(raw).toLocaleString('tr-TR', {
      dateStyle: 'short',
      timeStyle: 'short',
    });
  } catch {
    return raw;
  }
}

/* ------------------------------------------------------------------ */
/* GET /admin/login                                                     */
/* ------------------------------------------------------------------ */

router.get('/login', (req, res) => {
  if (req.session?.isAdmin) return res.redirect('/admin');
  res.send(renderLoginPage());
});

/* ------------------------------------------------------------------ */
/* POST /admin/login                                                    */
/* ------------------------------------------------------------------ */

router.post('/login', (req, res) => {
  const { username, password } = req.body;

  const validUser = process.env.ADMIN_USERNAME;
  const validPass = process.env.ADMIN_PASSWORD;

  if (!validUser || !validPass) {
    return res.send(renderLoginPage('Sunucuda admin kimlik bilgileri yapılandırılmamış. .env dosyasını kontrol edin.'));
  }

  if (username === validUser && password === validPass) {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }

  res.send(renderLoginPage('Kullanıcı adı veya şifre hatalı.'));
});

/* ------------------------------------------------------------------ */
/* GET /admin                                                           */
/* ------------------------------------------------------------------ */

router.get('/', requireAuth, (req, res) => {
  const scans = getRecentScans(200);
  res.send(renderAdminPage(scans));
});

/* ------------------------------------------------------------------ */
/* GET /admin/logout                                                    */
/* ------------------------------------------------------------------ */

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

/* ================================================================== */
/* HTML şablonları                                                      */
/* ================================================================== */

const BASE_STYLES = `
  :root {
    --bg: #0f1419;
    --bg-card: #1a2332;
    --bg-input: #0d1117;
    --border: #2d3a4f;
    --text: #e6edf3;
    --muted: #8b949e;
    --primary: #3b82f6;
    --primary-hover: #2563eb;
    --danger: #ef4444;
    --success: #22c55e;
    --warning: #eab308;
    --radius: 10px;
    --font: 'Segoe UI', system-ui, sans-serif;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: var(--font); background: var(--bg); color: var(--text); min-height: 100vh; }
  a { color: var(--primary); text-decoration: none; }
  a:hover { text-decoration: underline; }
`;

/* ---- Login sayfası HTML ---- */
function renderLoginPage(errorMsg = '') {
  return `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Giriş — IP Reputation Checker</title>
  <style>
    ${BASE_STYLES}
    .page {
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 1.5rem;
    }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 2rem 2.5rem;
      width: 100%; max-width: 380px;
      box-shadow: 0 4px 24px rgba(0,0,0,.35);
    }
    .logo { font-size: 2rem; text-align: center; margin-bottom: .5rem; }
    h1 { font-size: 1.25rem; font-weight: 700; text-align: center; margin-bottom: 1.75rem; }
    label { display: block; font-size: .8rem; color: var(--muted); margin-bottom: .35rem; font-weight: 500; }
    input {
      width: 100%; padding: .7rem .9rem; font-size: .95rem;
      background: var(--bg-input); border: 1px solid var(--border);
      border-radius: 7px; color: var(--text); outline: none;
      transition: border-color .2s;
    }
    input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59,130,246,.2); }
    .field { margin-bottom: 1rem; }
    .btn {
      display: block; width: 100%; padding: .75rem;
      background: var(--primary); color: #fff;
      border: none; border-radius: 7px; font-size: 1rem;
      font-weight: 600; cursor: pointer; margin-top: 1.5rem;
      transition: background .2s;
    }
    .btn:hover { background: var(--primary-hover); }
    .error {
      background: rgba(239,68,68,.12); border: 1px solid rgba(239,68,68,.35);
      color: #fca5a5; border-radius: 7px; padding: .65rem .9rem;
      font-size: .875rem; margin-bottom: 1rem;
    }
    .back { text-align: center; margin-top: 1.25rem; font-size: .85rem; color: var(--muted); }
  </style>
</head>
<body>
  <div class="page">
    <div class="card">
      <div class="logo">🛡️</div>
      <h1>Admin Girişi</h1>
      ${errorMsg ? `<div class="error">${errorMsg}</div>` : ''}
      <form method="POST" action="/admin/login">
        <div class="field">
          <label for="username">Kullanıcı Adı</label>
          <input type="text" id="username" name="username" autocomplete="username" required autofocus>
        </div>
        <div class="field">
          <label for="password">Şifre</label>
          <input type="password" id="password" name="password" autocomplete="current-password" required>
        </div>
        <button class="btn" type="submit">Giriş Yap</button>
      </form>
      <p class="back"><a href="/">← Ana sayfaya dön</a></p>
    </div>
  </div>
</body>
</html>`;
}

/* ---- Admin panel HTML ---- */
function renderAdminPage(scans) {
  const rows = scans.length === 0
    ? `<tr><td colspan="10" class="empty">Henüz kayıtlı tarama yok.</td></tr>`
    : scans.map(s => {
        const rc = riskClass(s.risk_level);
        return `<tr>
          <td class="mono nowrap">${fmtDate(s.created_at)}</td>
          <td class="mono">${s.ip_address}</td>
          <td><span class="badge badge--${rc}">${s.risk_level ?? '—'}</span></td>
          <td>${s.abuse_score ?? '—'}</td>
          <td>${s.country_code ?? '—'}</td>
          <td class="truncate" title="${s.isp ?? ''}">${s.isp ?? '—'}</td>
          <td>${s.otx_pulse_count ?? '—'}</td>
          <td>${s.vt_malicious ?? '—'}</td>
          <td class="mono">${s.visitor_ip ?? '—'}</td>
          <td>${s.visitor_country ?? '—'}</td>
        </tr>`;
      }).join('\n');

  return `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Panel — IP Reputation Checker</title>
  <style>
    ${BASE_STYLES}
    .topbar {
      display: flex; align-items: center; justify-content: space-between;
      padding: .85rem 1.5rem;
      background: var(--bg-card); border-bottom: 1px solid var(--border);
      gap: 1rem;
    }
    .topbar__brand { display: flex; align-items: center; gap: .5rem; font-weight: 700; font-size: 1.05rem; }
    .topbar__actions { display: flex; align-items: center; gap: 1rem; }
    .topbar__actions a { font-size: .85rem; color: var(--muted); }
    .topbar__actions a:hover { color: var(--danger); }
    .main { max-width: 1200px; margin: 0 auto; padding: 1.5rem 1.25rem 3rem; }
    .page-title {
      font-size: 1.1rem; font-weight: 700; margin-bottom: 1.25rem;
      display: flex; align-items: center; gap: .6rem;
    }
    .count-pill {
      font-size: .75rem; font-weight: 600; padding: .2rem .6rem;
      background: rgba(59,130,246,.15); color: var(--primary);
      border-radius: 999px;
    }
    .table-wrap {
      overflow-x: auto; overflow-y: auto; max-height: 70vh;
      border: 1px solid var(--border); border-radius: var(--radius);
      scrollbar-width: thin; scrollbar-color: var(--border) transparent;
    }
    table { width: 100%; border-collapse: collapse; font-size: .85rem; min-width: 750px; }
    thead { background: var(--bg-input); position: sticky; top: 0; z-index: 1; }
    th {
      text-align: left; padding: .7rem 1rem; font-weight: 600;
      color: var(--muted); border-bottom: 1px solid var(--border); white-space: nowrap;
    }
    td { padding: .7rem 1rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tbody tr:last-child td { border-bottom: none; }
    tbody tr:hover { background: rgba(59,130,246,.04); }
    .mono { font-family: 'Consolas', 'Monaco', monospace; }
    .nowrap { white-space: nowrap; }
    .truncate { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .empty { text-align: center; color: var(--muted); padding: 2rem !important; }
    /* Risk rozetleri */
    .badge { display: inline-block; padding: .2rem .55rem; border-radius: 999px; font-size: .75rem; font-weight: 600; }
    .badge--clean    { background: rgba(34,197,94,.15);  color: var(--success); }
    .badge--low      { background: rgba(59,130,246,.15); color: #60a5fa; }
    .badge--medium   { background: rgba(234,179,8,.15);  color: var(--warning); }
    .badge--high     { background: rgba(239,68,68,.15);  color: var(--danger); }
    .badge--unknown  { background: rgba(139,148,158,.15); color: var(--muted); }
    .empty-state { text-align: center; padding: 4rem 1rem; color: var(--muted); font-size: .95rem; }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar__brand">🛡️ IP Reputation Checker</div>
    <div class="topbar__actions">
      <a href="/">Ana Sayfa</a>
      <a href="/admin/logout">Çıkış Yap</a>
    </div>
  </header>

  <main class="main">
    <div class="page-title">
      Son Taramalar
      <span class="count-pill">${scans.length} kayıt</span>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Tarih / Saat</th>
            <th>IP Adresi</th>
            <th>Risk</th>
            <th>Abuse Score</th>
            <th>Country</th>
            <th>ISP</th>
            <th>OTX Pulses</th>
            <th>VT Malicious</th>
            <th>Visitor IP</th>
            <th>Visitor Country</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
  </main>
</body>
</html>`;
}

module.exports = router;
