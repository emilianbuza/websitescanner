// database.js
// Scan-History mit SQLite3

import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { existsSync, mkdirSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DATA_DIR = join(__dirname, 'data');
if (!existsSync(DATA_DIR)) {
  mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = join(DATA_DIR, 'scans.db');
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    scan_data TEXT NOT NULL,
    summary_json TEXT,
    score INTEGER,
    critical_issues INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_url ON scans(url);
  CREATE INDEX IF NOT EXISTS idx_created_at ON scans(created_at DESC);
`);

export function saveScan(url, scanData) {
  const summary = scanData.summary || {};
  const score = calculateScore(scanData);
  const criticalIssues = scanData.summary?.highPriorityIssues || 0;

  const stmt = db.prepare(`
    INSERT INTO scans (url, timestamp, scan_data, summary_json, score, critical_issues)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    url,
    scanData.timestamp || new Date().toISOString(),
    JSON.stringify(scanData),
    JSON.stringify(summary),
    score,
    criticalIssues
  );

  return result.lastInsertRowid;
}

export function getScanHistory(limit = 20) {
  const stmt = db.prepare(`
    SELECT
      id,
      url,
      timestamp,
      score,
      critical_issues,
      created_at
    FROM scans
    ORDER BY created_at DESC
    LIMIT ?
  `);

  return stmt.all(limit);
}

export function getScansByUrl(url, limit = 10) {
  const stmt = db.prepare(`
    SELECT
      id,
      url,
      timestamp,
      score,
      critical_issues,
      created_at,
      scan_data
    FROM scans
    WHERE url = ?
    ORDER BY created_at DESC
    LIMIT ?
  `);

  const rows = stmt.all(url, limit);
  return rows.map(row => ({
    ...row,
    scan_data: JSON.parse(row.scan_data)
  }));
}

export function getScanById(id) {
  const stmt = db.prepare(`
    SELECT *
    FROM scans
    WHERE id = ?
  `);

  const row = stmt.get(id);
  if (!row) return null;

  return {
    ...row,
    scan_data: JSON.parse(row.scan_data),
    summary_json: row.summary_json ? JSON.parse(row.summary_json) : null
  };
}

export function compareScans(id1, id2) {
  const scan1 = getScanById(id1);
  const scan2 = getScanById(id2);

  if (!scan1 || !scan2) {
    throw new Error('One or both scans not found');
  }

  return {
    scan1: {
      id: scan1.id,
      url: scan1.url,
      timestamp: scan1.timestamp,
      score: scan1.score,
      criticalIssues: scan1.critical_issues
    },
    scan2: {
      id: scan2.id,
      url: scan2.url,
      timestamp: scan2.timestamp,
      score: scan2.score,
      criticalIssues: scan2.critical_issues
    },
    improvements: {
      scoreChange: scan2.score - scan1.score,
      criticalIssuesChange: scan2.critical_issues - scan1.critical_issues
    },
    details: {
      scan1Data: scan1.scan_data,
      scan2Data: scan2.scan_data
    }
  };
}

export function getStats() {
  const stmt = db.prepare(`
    SELECT
      COUNT(*) as total_scans,
      COUNT(DISTINCT url) as unique_urls,
      AVG(score) as avg_score,
      AVG(critical_issues) as avg_critical
    FROM scans
  `);

  return stmt.get();
}

export function deleteScan(id) {
  const stmt = db.prepare('DELETE FROM scans WHERE id = ?');
  return stmt.run(id);
}

export function cleanOldScans(daysToKeep = 90) {
  const stmt = db.prepare(`
    DELETE FROM scans
    WHERE created_at < datetime('now', '-' || ? || ' days')
  `);

  return stmt.run(daysToKeep);
}

function calculateScore(scanData) {
  let score = 100;

  const criticalIssues = scanData.summary?.highPriorityIssues || 0;
  const totalIssues = scanData.summary?.totalIssues || 0;
  const marketingTags = scanData.summary?.marketingTags || [];

  // Deduct points for issues
  score -= criticalIssues * 15;
  score -= totalIssues * 2;

  // Deduct for compliance issues
  const badCompliance = marketingTags.filter(t => t.compliance === 'bad').length;
  const inconsistent = marketingTags.filter(t => t.compliance === 'inconsistent').length;

  score -= badCompliance * 10;
  score -= inconsistent * 5;

  return Math.max(0, Math.min(100, score));
}

export default db;
