/**
 * /check endpoint route tanımı.
 * Frontend'den gelen IP sorgularını alır, doğrular ve AbuseIPDB'ye iletir.
 */

const express = require('express');
const { isValidIp, normalizeIp } = require('../utils/ipValidator');
const { getRiskLevel } = require('../utils/riskLevel');
const { checkIpReputation } = require('../services/abuseIpDb');
const { checkIpOtx } = require('../services/otx');
const { checkIpVirusTotal } = require('../services/virustotal');
const { insertScan } = require('../db/database');
const geoip = require('geoip-lite');

const router = express.Router();

/**
 * POST /check
 * Body: { "ip": "8.8.8.8" }
 *
 * Başarılı yanıt örneği:
 * {
 *   "success": true,
 *   "data": {
 *     "ipAddress": "8.8.8.8",
 *     "abuseConfidenceScore": 0,
 *     "countryCode": "US",
 *     "isp": "...",
 *     "domain": "...",
 *     "totalReports": 0,
 *     "lastReportedAt": null,
 *     "riskLevel": { "level": "clean", "label": "Temiz" }
 *   }
 * }
 */
router.post('/', async (req, res) => {
  const rawIp = req.body?.ip;

  // Boş IP kontrolü
  if (!rawIp || typeof rawIp !== 'string' || rawIp.trim() === '') {
    return res.status(400).json({
      success: false,
      error: {
        code: 'EMPTY_IP',
        message: 'Lütfen bir IP adresi girin.',
      },
    });
  }

  // Tek istekte gönderilebilecek maksimum IP sayısı kontrolü
  // (Doğrudan API erişiminde çok sayıda IP gönderilmesini engeller)
  const maxIps = parseInt(process.env.MAX_IPS_PER_REQUEST) || 10;
  const ipLineCount = rawIp.split('\n').filter(l => l.trim() !== '').length;
  if (ipLineCount > maxIps) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'TOO_MANY_IPS',
        message: `Tek bir istekte en fazla ${maxIps} IP sorgulanabilir. ${ipLineCount} IP gönderildi.`,
      },
    });
  }

  const ip = normalizeIp(rawIp);

  // Geçersiz IP formatı kontrolü
  if (!isValidIp(ip)) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'INVALID_IP',
        message: 'Geçersiz IP adresi. Lütfen geçerli bir IPv4 veya IPv6 adresi girin.',
      },
    });
  }

  // API anahtarı .env dosyasından okunur
  const apiKey = process.env.ABUSEIPDB_API_KEY;

  if (!apiKey || apiKey.trim() === '' || apiKey === 'your_api_key_here') {
    return res.status(500).json({
      success: false,
      error: {
        code: 'MISSING_API_KEY',
        message:
          'Sunucuda API anahtarı yapılandırılmamış. backend/.env dosyasına ABUSEIPDB_API_KEY ekleyin.',
      },
    });
  }

  try {
    const otxApiKey = process.env.OTX_API_KEY;
    const vtApiKey  = process.env.VT_API_KEY;

    const otxConfigured = !!(otxApiKey && otxApiKey.trim() !== '' && otxApiKey !== 'your_otx_api_key_here');
    const vtConfigured  = !!(vtApiKey  && vtApiKey.trim()  !== '' && vtApiKey  !== 'your_virustotal_api_key_here');

    // Performans ölçümü: her promise'i süre kaydeden sarmalayıcıya al
    const totalStart = Date.now();
    let msAbuse = 0, msOtx = 0, msVt = 0;

    const timedAbuse = () => {
      const t = Date.now();
      return checkIpReputation(ip, apiKey.trim()).then(r => { msAbuse = Date.now() - t; return r; });
    };

    const timedOtx = otxConfigured
      ? () => { const t = Date.now(); return checkIpOtx(ip, otxApiKey.trim()).then(r => { msOtx = Date.now() - t; return r; }); }
      : () => Promise.resolve({ available: false, error: 'Yapılandırılmadı' });

    const timedVt = vtConfigured
      ? () => { const t = Date.now(); return checkIpVirusTotal(ip, vtApiKey.trim()).then(r => { msVt = Date.now() - t; return r; }); }
      : () => Promise.resolve({ available: false, error: 'Yapılandırılmadı' });

    // Üç API çağrısı aynı anda başlatılır.
    // AbuseIPDB hata fırlatırsa Promise.all reddedilir ve catch bloğuna düşer.
    // OTX ve VT kendi içlerinde hataları yutarak { available: false } döndürür.
    const [result, otx, virustotal] = await Promise.all([
      timedAbuse(),
      timedOtx(),
      timedVt(),
    ]);

    const msTotal = Date.now() - totalStart;

    // Performans logları: yalnızca PERF_LOGS=true ise terminale yazdırılır
    if (process.env.PERF_LOGS === 'true') {
      console.log(`[PERF] IP: ${ip}`);
      console.log(`[PERF] AbuseIPDB:  ${msAbuse} ms`);
      console.log(`[PERF] OTX:        ${otxConfigured ? msOtx + ' ms' : 'yapılandırılmadı'}`);
      console.log(`[PERF] VirusTotal: ${vtConfigured  ? msVt  + ' ms' : 'yapılandırılmadı'}`);
      console.log(`[PERF] Total:      ${msTotal} ms`);
    }

    // riskLevel yine AbuseIPDB sonucundan hesaplanır
    const riskLevel = getRiskLevel(result.abuseConfidenceScore);

    const responseData = { ...result, riskLevel, otx, virustotal };

    // Ziyaretçi IP'sini belirle: önce X-Forwarded-For, sonra req.ip
    const forwarded = req.headers['x-forwarded-for'];
    const visitorIp = forwarded
      ? forwarded.split(',')[0].trim()
      : (req.ip || null);

    // Ziyaretçi ülkesini geoip-lite ile bul
    let visitorCountry;
    if (!visitorIp || visitorIp === '::1' || visitorIp === '127.0.0.1') {
      visitorCountry = 'Localhost';
    } else {
      const geo = geoip.lookup(visitorIp);
      visitorCountry = geo?.country ?? 'Unknown';
    }

    // Başarılı sorguyu SQLite'a kaydet (hata olursa yanıtı etkilemez)
    try {
      insertScan(responseData, visitorIp, visitorCountry);
    } catch (dbErr) {
      console.error('[DB] Kayıt hatası:', dbErr.message);
    }

    return res.json({ success: true, data: responseData });
  } catch (error) {
    // Bilinen hata kodlarına göre uygun HTTP durum kodu seç
    const statusByCode = {
      RATE_LIMIT: 429,
      INVALID_API_KEY: 500,
      NETWORK_ERROR: 503,
      API_ERROR: 502,
    };

    const status = statusByCode[error.code] || 500;

    return res.status(status).json({
      success: false,
      error: {
        code: error.code || 'UNKNOWN_ERROR',
        message: error.message || 'Beklenmeyen bir hata oluştu.',
      },
    });
  }
});

module.exports = router;
