/**
 * SQLite veritabanı kurulumu ve yardımcı fonksiyonlar.
 *
 * better-sqlite3 senkron API kullanır; async/await gerekmez.
 * DB dosyası: backend/data/scans.db
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// data/ klasörü yoksa oluştur
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const DB_PATH = path.join(dataDir, 'scans.db');

// Veritabanı bağlantısını aç (dosya yoksa otomatik oluşturulur)
const db = new Database(DB_PATH);

// WAL modu: eş zamanlı okuma performansını artırır
db.pragma('journal_mode = WAL');

// Tarama kayıtları tablosunu oluştur (zaten varsa atla)
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address       TEXT    NOT NULL,
    abuse_score      INTEGER,
    risk_level       TEXT,
    country_code     TEXT,
    isp              TEXT,
    domain           TEXT,
    total_reports    INTEGER,
    last_reported_at TEXT,
    otx_pulse_count  INTEGER,
    otx_reputation   INTEGER,
    vt_malicious     INTEGER,
    vt_suspicious    INTEGER,
    vt_harmless      INTEGER,
    vt_undetected    INTEGER,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
  )
`);

// Migration: visitor_ip ve visitor_country sütunları yoksa ekle.
// ALTER TABLE IF NOT EXISTS sadece SQLite 3.37+ destekler;
// sütun listesini kontrol ederek uyumlu şekilde yapıyoruz.
const existingColumns = db.pragma('table_info(scans)').map(c => c.name);
if (!existingColumns.includes('visitor_ip')) {
  db.exec('ALTER TABLE scans ADD COLUMN visitor_ip TEXT');
}
if (!existingColumns.includes('visitor_country')) {
  db.exec('ALTER TABLE scans ADD COLUMN visitor_country TEXT');
}

/**
 * Başarılı bir IP taramasını veritabanına kaydeder.
 * @param {object} data        - /check endpoint'inden dönen data objesi
 * @param {string} visitorIp      - İsteği gönderen ziyaretçinin IP adresi
 * @param {string} visitorCountry - Ziyaretçinin ülke kodu (geoip-lite veya özel değer)
 */
function insertScan(data, visitorIp = null, visitorCountry = null) {
  const stmt = db.prepare(`
    INSERT INTO scans (
      ip_address, abuse_score, risk_level, country_code,
      isp, domain, total_reports, last_reported_at,
      otx_pulse_count, otx_reputation,
      vt_malicious, vt_suspicious, vt_harmless, vt_undetected,
      visitor_ip, visitor_country
    ) VALUES (
      @ip_address, @abuse_score, @risk_level, @country_code,
      @isp, @domain, @total_reports, @last_reported_at,
      @otx_pulse_count, @otx_reputation,
      @vt_malicious, @vt_suspicious, @vt_harmless, @vt_undetected,
      @visitor_ip, @visitor_country
    )
  `);

  stmt.run({
    ip_address:       data.ipAddress ?? '',
    abuse_score:      data.abuseConfidenceScore ?? 0,
    risk_level:       data.riskLevel?.level ?? 'unknown',
    country_code:     data.countryCode ?? null,
    isp:              data.isp ?? null,
    domain:           data.domain ?? null,
    total_reports:    data.totalReports ?? 0,
    last_reported_at: data.lastReportedAt ?? null,
    otx_pulse_count:  data.otx?.available ? (data.otx.pulseCount ?? 0) : null,
    otx_reputation:   data.otx?.available ? (data.otx.reputation ?? 0) : null,
    vt_malicious:     data.virustotal?.available ? (data.virustotal.malicious ?? 0) : null,
    vt_suspicious:    data.virustotal?.available ? (data.virustotal.suspicious ?? 0) : null,
    vt_harmless:      data.virustotal?.available ? (data.virustotal.harmless ?? 0) : null,
    vt_undetected:    data.virustotal?.available ? (data.virustotal.undetected ?? 0) : null,
    visitor_ip:       visitorIp,
    visitor_country:  visitorCountry,
  });
}

/**
 * En son yapılan taramaları döndürür (en yeni önce).
 * @param {number} limit - Maksimum kayıt sayısı (varsayılan 100)
 * @returns {object[]} Tarama kayıtları dizisi
 */
function getRecentScans(limit = 100) {
  return db.prepare(
    'SELECT * FROM scans ORDER BY id DESC LIMIT ?'
  ).all(limit);
}

module.exports = { insertScan, getRecentScans };
