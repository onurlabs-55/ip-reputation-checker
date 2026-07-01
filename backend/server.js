/**
 * IP Reputation Checker - Ana sunucu dosyası
 *
 * Express ile:
 *  - POST /check       → IP itibar sorgusu (AbuseIPDB + OTX + VirusTotal)
 *  - GET  /admin       → Admin paneli (oturum gerekli)
 *  - GET  /admin/login → Admin giriş sayfası
 *  - Statik dosyalar   → ../frontend klasöründen servis edilir
 */

require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const session = require('express-session');

const { rateLimit } = require('express-rate-limit');
const checkRoute = require('./routes/check');
const adminRoute = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 3000;

// JSON istek gövdelerini parse et (API istekleri için)
app.use(express.json());

// URL-encoded form gövdelerini parse et (admin login formu için)
app.use(express.urlencoded({ extended: false }));

// Geliştirme sırasında farklı porttan erişim için CORS
app.use(cors());

// Oturum yönetimi (admin paneli için)
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,          // XSS koruması: JS ile erişilemesin
    secure: false,           // HTTPS zorunluluğu yok (geliştirme ortamı)
    maxAge: 1000 * 60 * 60, // 1 saat
  },
}));

// Rate limit: yalnızca POST /check için geçerli
// Pencere ve limit .env üzerinden yapılandırılabilir
const checkRateLimit = rateLimit({
  windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW_MINUTES) || 1) * 60 * 1000,
  max:      parseInt(process.env.RATE_LIMIT_MAX_REQUESTS)    || 20,
  standardHeaders: true,  // RateLimit-* headerları ekler
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: {
        code: 'RATE_LIMIT',
        message: `Çok fazla istek gönderildi. Lütfen ${process.env.RATE_LIMIT_WINDOW_MINUTES || 1} dakika sonra tekrar deneyin.`,
      },
    });
  },
});

// API endpoint'i
app.use('/check', checkRateLimit, checkRoute);

// Admin panel route'ları
app.use('/admin', adminRoute);

// Frontend statik dosyalarını servis et (HTML, CSS, JS)
const frontendPath = path.join(__dirname, '..', 'frontend');
app.use(express.static(frontendPath));

// /admin altındaki bilinmeyen rotalar login'e yönlendir
app.get('/admin/*', (req, res) => {
  res.redirect('/admin/login');
});

// Diğer tüm rotalar için ana sayfaya yönlendir
app.get('*', (req, res) => {
  res.sendFile(path.join(frontendPath, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`IP Reputation Checker çalışıyor: http://localhost:${PORT}`);
  console.log(`API endpoint:  POST http://localhost:${PORT}/check`);
  console.log(`Admin paneli:  http://localhost:${PORT}/admin/login`);
});
