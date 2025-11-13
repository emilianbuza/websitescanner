import express from 'express';
import { chromium } from 'playwright';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import { collectAllForCurrentState } from './ScannerModules.js';
import { formatReport } from './ReportFormatter.js';
import { saveScan, getScanHistory, getScansByUrl, getScanById, compareScans, getStats, deleteScan } from './database.js';
import { generatePDF } from './pdfExport.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import fs from 'fs';
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// Set browser path BEFORE any Playwright operations
const BROWSER_PATH = process.env.PLAYWRIGHT_BROWSERS_PATH || path.join(__dirname, '.playwright-browsers');
process.env.PLAYWRIGHT_BROWSERS_PATH = BROWSER_PATH;
console.log(`🎯 Setting PLAYWRIGHT_BROWSERS_PATH to: ${BROWSER_PATH}`);

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const VERSION = process.env.GIT_SHA || '2.4.0';

/* ------------------------- Rate limiting & middleware ------------------------- */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Rate limit exceeded. Max 20 scans per 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use('/scan', limiter);
app.use(express.static(path.join(__dirname, 'public')));

/* -------------------- HIT-based consent evaluation helpers ------------------- */
const TAG_META = {
  hasGA4:        { hitKey: 'hasGA4_HIT',        label: 'Google Analytics 4',      hitRegex: /(www|region\d+)\.google-analytics\.com\/g\/collect/i,      domains: ['google-analytics.com', 'g.doubleclick.net'] },
  hasUA:         { hitKey: 'hasUA_HIT',         label: 'Google Analytics (UA)',   hitRegex: /google-analytics\.com\/collect(\?|$)/i,                      domains: ['google-analytics.com'] },
  hasGoogleAds:  { hitKey: 'hasAds_HIT',        label: 'Google Ads',              hitRegex: /(googleadservices|googlesyndication)\.com/i,                domains: ['googleadservices.com','googlesyndication.com'] },
  hasMetaPixel:  { hitKey: 'hasMeta_HIT',       label: 'Meta Pixel',              hitRegex: /(facebook\.com\/tr|connect\.facebook\.net)/i,               domains: ['facebook.com','connect.facebook.net'] },
  hasTikTokPixel:{ hitKey: 'hasTikTok_HIT',     label: 'TikTok Pixel',            hitRegex: /analytics\.tiktok\.com/i,                                   domains: ['analytics.tiktok.com'] },
  hasHotjar:     { hitKey: 'hasHotjar_HIT',     label: 'Hotjar',                  hitRegex: /(static|script)\.hotjar\.com/i,                             domains: ['static.hotjar.com','script.hotjar.com'] },
  hasCrazyEgg:   { hitKey: 'hasCrazyEgg_HIT',   label: 'CrazyEgg',                hitRegex: /script\.crazyegg\.com/i,                                    domains: ['script.crazyegg.com'] },
  // GTM hat keinen eindeutigen Hit-Endpoint → Sonderfall
};
const COOKIE_HINTS = [
  /^_ga($|_)/i, /^_gid$/i, /^_gat/i, /^_gcl_/i, /^IDE$/i,
  /^_fbp$/i, /^_fbc$/i,
  /^_hj/i,
  /^tt(_|$)/i
];

function cspBlockedForDomains(modeResult, domains = []) {
  if (!modeResult?.cspViolations?.length) return false;
  return modeResult.cspViolations.some(v => {
    const msg = (v?.message || '') + ' ' + (v?.violation?.blockedURI || v?.blockedURI || '');
    try {
      const uri = v?.violation?.blockedURI || v?.blockedURI || '';
      const u = uri ? new URL(uri) : null;
      return domains.some(d => (u && u.hostname && u.hostname.includes(d)) || msg.includes(d));
    } catch {
      return domains.some(d => msg.includes(d));
    }
  });
}
function lastDlEvents(modeResult) {
  return modeResult?.marketingTags?.advanced?.domDetection?.dlEvents || [];
}
function getHit(modeResult, hitKey) {
  return !!modeResult?.marketingTags?.advanced?.networkDetection?.[hitKey];
}
function getLibPresent(modeResult, tagProperty) {
  return !!modeResult?.marketingTags?.[tagProperty];
}
function cookieDiff(before = [], after = []) {
  const b = new Map(before.map(c => [c.name + '@' + (c.domain||''), c]));
  const a = new Map(after.map(c => [c.name + '@' + (c.domain||''), c]));
  const added = [];
  for (const [k, v] of a.entries()) if (!b.has(k)) added.push(v);
  return added;
}
function highlightCookies(cookies = []) {
  return cookies
    .filter(c => COOKIE_HINTS.some(re => re.test(c.name)))
    .map(c => `${c.name} (Domain: ${c.domain || 'n/a'})`);
}

/* ---------------------------------- Scanner --------------------------------- */

class UltimateWebsiteScanner {
  constructor() { this.reset(); }

  reset() {
    this.errors = [];
    this.networkIssues = [];
    this.marketingTags = [];
    this.results = { withoutConsent: null, withConsent: null, withReject: null };
  }

  validateUrl(url) {
    try {
      const u = new URL(url);
      if (!/^https?:$/.test(u.protocol)) throw new Error('Only HTTP/HTTPS URLs allowed');
      const hostname = u.hostname.toLowerCase();
      if (/(^|\.)(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)/.test(hostname))
        throw new Error('Private/internal IPs not allowed');
      if (/^\[?::1\]?$/.test(hostname)) throw new Error('Loopback IPv6 not allowed');
      if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        const p = hostname.split('.').map(Number);
        if (p[0] === 127 || p[0] === 10 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31))
          throw new Error('Private IP ranges not allowed');
      }
      return true;
    } catch (error) {
      throw new Error('Invalid URL: ' + error.message);
    }
  }

  async scanWithRetry(url, maxRetries = 2) {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try { return await this.scan(url); }
      catch (error) {
        if (attempt === maxRetries) throw error;
        console.log(`Retry ${attempt + 1}/${maxRetries} for ${url} — ${error.message}`);
        await new Promise(res => setTimeout(res, 3000));
      }
    }
  }

  async scan(url) {
    this.reset();
    this.validateUrl(url);
    console.log(`🔍 Starting comprehensive scan of ${url}`);

    let browser;
    try {
      console.log('🌐 Launching Chromium browser...');
      browser = await chromium.launch({
        headless: true,
        args: ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage','--disable-web-security','--disable-features=VizDisplayCompositor']
      });
      console.log('✅ Browser launched successfully');
    } catch (launchError) {
      console.error('❌ Failed to launch browser:', launchError.message);
      console.error('Browser executable path:', chromium.executablePath());
      throw new Error(`Browser launch failed: ${launchError.message}`);
    }

    try {
      console.log('🚫 Run A: Scanning without consent (default denied)...');
      this.results.withoutConsent = await this.runSingleScan(browser, url, 'no-consent');

      console.log('✅ Run B: Scanning with consent accepted...');
      this.results.withConsent = await this.runSingleScan(browser, url, 'accept');

      console.log('❌ Run C: Scanning with consent rejected...');
      this.results.withReject = await this.runSingleScan(browser, url, 'reject');

      this.analyzeConsentCompliance();
      this.attachEvidence(url); // baut Belege/Quellen auf
    } finally {
      await browser.close();
    }

    return this.getComprehensiveResults(url);
  }

  async runSingleScan(browser, url, consentMode) {
    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      viewport: { width: 1920, height: 1080 },
      ignoreHTTPSErrors: true
    });

    if (consentMode === 'reject') await this.setConsentCookies(context, url, false);
    else if (consentMode === 'accept') await this.setConsentCookies(context, url, true);

    const page = await context.newPage();
    const scanData = {
      errors: [],
      networkIssues: [],
      cspViolations: [],
      marketingTags: {},
      requestLog: [],
      cookiesBefore: [],
      cookiesAfter: [],
      consentMode
    };

    await page.addInitScript(() => {
      window.__cspViolations = [];
      window.__fetchLog = [];
      window.addEventListener('securitypolicyviolation', e => {
        window.__cspViolations.push({
          blockedURI: e.blockedURI,
          violatedDirective: e.violatedDirective,
          lineNumber: e.lineNumber || 0,
          sourceFile: e.sourceFile || '',
          originalPolicy: e.originalPolicy
        });
      });
      const _fetch = window.fetch;
      window.fetch = async (...args) => {
        const started = Date.now();
        try {
          const res = await _fetch(...args);
          try {
            const url = (args && args[0] && args[0].url) || String(args[0]);
            window.__fetchLog.push({ url, status: res.status || 0, method: (args[1]?.method || 'GET'), ts: started });
          } catch {}
          return res;
        } catch (err) {
          try {
            const url = (args && args[0] && args[0].url) || String(args[0]);
            window.__fetchLog.push({ url, status: 0, method: (args[1]?.method || 'GET'), error: String(err), ts: started });
          } catch {}
          throw err;
        }
      };
    });

    page.on('console', msg => {
      if (msg.type() === 'error') {
        const text = msg.text() || '';
        scanData.errors.push({
          type: 'Console Error',
          message: text,
          location: msg.location(),
          priority: this.classifyErrorPriority(text),
          translation: this.translateError(text),
          techFix: this.suggestFix(text),
          consentMode
        });
      }
    });

    page.on('pageerror', error => {
      scanData.errors.push({
        type: 'Uncaught Error',
        message: String(error),
        priority: 'high',
        translation: 'JavaScript-Fehler kann Funktionen/Tracking bremsen',
        techFix: 'Fehlerstack im Browser prüfen, betroffene Datei fixen',
        consentMode
      });
    });

    page.on('requestfinished', async request => {
      const started = request.timing()?.startTime ? Date.now() - Math.round(request.timing().startTime) : Date.now();
      try {
        const response = await request.response();
        const status = response ? response.status() : 0;
        const rt = typeof request.resourceType === 'function' ? request.resourceType() : (request.resourceType || 'unknown');
        scanData.requestLog.push({ url: request.url(), method: request.method(), resourceType: rt, status, ts: started });
      } catch (e) {
        const rt = typeof request.resourceType === 'function' ? request.resourceType() : (request.resourceType || 'unknown');
        scanData.requestLog.push({ url: request.url(), method: request.method(), resourceType: rt, status: 0, ts: started, note: 'requestfinished handler error: ' + String(e) });
      }
    });

    page.on('requestfailed', request => {
      const failure = request.failure();
      const rt = typeof request.resourceType === 'function' ? request.resourceType() : (request.resourceType || 'unknown');
      scanData.networkIssues.push({
        url: request.url(),
        method: request.method(),
        resourceType: rt,
        status: failure?.errorText || 'Request Failed',
        priority: this.classifyNetworkPriority(request.url()),
        translation: this.translateNetworkIssue(request.url(), failure?.errorText || ''),
        techFix: this.suggestFixForUrl(request.url(), failure?.errorText),
        consentMode,
        ts: Date.now()
      });
    });

    page.on('response', response => {
      try {
        if (response.status() >= 400) {
          scanData.networkIssues.push({
            url: response.url(),
            status: response.status(),
            priority: this.classifyNetworkPriority(response.url()),
            translation: this.translateNetworkIssue(response.url(), String(response.status())),
            techFix: this.suggestFixForUrl(response.url(), String(response.status())),
            consentMode,
            ts: Date.now()
          });
        }
      } catch {}
    });

    try {
      scanData.cookiesBefore = await context.cookies(url);

      if (consentMode === 'no-consent') {
        await page.addInitScript(() => {
          window.dataLayer = window.dataLayer || [];
          function gtag(){window.dataLayer.push(arguments);}
          gtag('consent','default',{
            ad_storage:'denied',
            ad_user_data:'denied',
            ad_personalization:'denied',
            analytics_storage:'denied',
            functionality_storage:'granted',
            security_storage:'granted'
          });
        });
      }

      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 25000 });

      if (consentMode === 'accept') {
        await this.handleConsent(page, 'accept');
        await page.evaluate(() => {
          window.dataLayer = window.dataLayer || [];
          function gtag(){window.dataLayer.push(arguments);}
          gtag('consent','update',{
            ad_storage:'granted',
            ad_user_data:'granted',
            ad_personalization:'granted',
            analytics_storage:'granted'
          });
        });
      } else if (consentMode === 'reject') {
        await this.handleConsent(page, 'reject');
        await page.evaluate(() => {
          window.dataLayer = window.dataLayer || [];
          function gtag(){window.dataLayer.push(arguments);}
          gtag('consent','update',{
            ad_storage:'denied',
            ad_user_data:'denied',
            ad_personalization:'denied',
            analytics_storage:'denied'
          });
        });
      }

      await page.evaluate(() => { window.scrollTo(0, document.body.scrollHeight); });
      await Promise.race([
        page.waitForLoadState('networkidle', { timeout: 4000 }).catch(() => {}),
        page.waitForTimeout(2000)
      ]);

      const fetchLog = await page.evaluate(() => window.__fetchLog.slice());
      for (const f of fetchLog) {
        scanData.requestLog.push({
          url: f.url,
          method: f.method || 'GET',
          resourceType: 'fetch',
          status: f.status || 0,
          ts: f.ts || Date.now()
        });
      }

      scanData.marketingTags = await this.checkMarketingTagsDeep(page, scanData.requestLog);

      const cspViolations = await page.evaluate(() => window.__cspViolations.slice());
      scanData.cspViolations = cspViolations.map(v => ({
        type: 'CSP Violation',
        message: `${v.violatedDirective} blocked ${v.blockedURI} @line:${v.lineNumber}`,
        priority: 'high',
        translation: '🔒 Sicherheitsrichtlinie blockiert Verbindungen zu einem Dienst',
        techFix: this.suggestCSPFix(v),
        violation: v,
        consentMode,
        ts: Date.now()
      }));

      scanData.cookiesAfter = await context.cookies(url);

    } catch (error) {
      scanData.errors.push({
        type: 'Page Load Error',
        message: error.message,
        priority: 'critical',
        translation: 'Website nicht erreichbar - kritischer Umsatzverlust!',
        techFix: 'Domain, SSL-Zertifikat und Server-Erreichbarkeit prüfen',
        consentMode
      });
    }

    await context.close();
    return scanData;
  }

  async setConsentCookies(context, url, acceptAll) {
    const domain = new URL(url).hostname;
    const consentCookies = [
      { name: 'CookieConsent', value: JSON.stringify({ stamp: Date.now(), necessary: true, preferences: acceptAll, statistics: acceptAll, marketing: acceptAll, method: 'explicit' }), domain, path: '/' },
      { name: 'cookielawinfo-checkbox-necessary', value: 'yes', domain, path: '/' },
      { name: 'cookielawinfo-checkbox-analytics', value: acceptAll ? 'yes' : 'no', domain, path: '/' },
      { name: 'cookielawinfo-checkbox-advertisement', value: acceptAll ? 'yes' : 'no', domain, path: '/' }
    ];
    for (const c of consentCookies) { try { await context.addCookies([c]); } catch {} }
  }

  async handleConsent(page, action) {
    try {
      await page.waitForTimeout(1800);
      const selectors = ['button','[role="button"]','input[type="button"]','a[href]','[onclick]','div[role="button"]','span[role="button"]'];
      const elements = await page.$$(selectors.join(','));
      const ACCEPT_RE = /accept|zustimmen|einverstanden|alle.*(zulassen|akzeptieren)|ok|verstanden|allow.*all/i;
      const REJECT_RE = /reject|ablehnen|nur.*(notwendig|necessary|minimal)|essential.*only|necessary.*only/i;

      for (const el of elements) {
        const text = (await el.textContent())?.toLowerCase() || '';
        const aria = (await el.getAttribute('aria-label'))?.toLowerCase() || '';
        const cls  = (await el.getAttribute('class'))?.toLowerCase() || '';
        const id   = (await el.getAttribute('id'))?.toLowerCase() || '';
        const hay = `${text} ${aria} ${cls} ${id}`;
        const isVisible = await el.isVisible().catch(() => false);
        if (!isVisible) continue;

        if (action === 'accept' && ACCEPT_RE.test(hay)) { await el.click({ delay: 10 }); await page.waitForTimeout(1500); return true; }
        if (action === 'reject' && REJECT_RE.test(hay)) { await el.click({ delay: 10 }); await page.waitForTimeout(1500); return true; }
      }
      return false;
    } catch (e) {
      console.log(`Consent handling failed: ${e.message}`); return false;
    }
  }

  async checkMarketingTagsDeep(page, requestLog) {
    const hasGA4_HIT = requestLog.some(r => /(www|region\d+)\.google-analytics\.com\/g\/collect/i.test(r.url));
    const hasGA4_LIB = requestLog.some(r => /gtag\/js\?id=G-/i.test(r.url));
    const hasUA_HIT  = requestLog.some(r => /google-analytics\.com\/collect(\?|$)/i.test(r.url));
    const hasUA_LIB  = requestLog.some(r => /google-analytics\.com\/analytics\.js/i.test(r.url));
    const hasGTM_NET = requestLog.some(r => /googletagmanager\.com\/gtm\.js/i.test(r.url));

    const hasAds_HIT = requestLog.some(r => /(googleadservices|googlesyndication)\.com/i.test(r.url));
    const hasMeta_HIT = requestLog.some(r => /facebook\.com\/tr/i.test(r.url));
    const hasMeta_LIB = requestLog.some(r => /connect\.facebook\.net/i.test(r.url));
    const hasTikTok_HIT = requestLog.some(r => /analytics\.tiktok\.com/i.test(r.url));
    const hasHotjar_HIT = requestLog.some(r => /(static|script)\.hotjar\.com/i.test(r.url));
    const hasCrazyEgg_HIT = requestLog.some(r => /script\.crazyegg\.com/i.test(r.url));

    const domBasedDetection = await page.evaluate(() => {
      const scripts = [...document.scripts];
      const iframes = [...document.querySelectorAll('iframe')];

      const hasGA4 = scripts.some(s => /gtag\/js\?id=G-/i.test(s.src)) || typeof window.gtag === 'function';
      const hasUA  = scripts.some(s => /google-analytics\.com\/analytics\.js/i.test(s.src)) || typeof window.ga === 'function';
      const hasGTM = scripts.some(s => /googletagmanager\.com\/gtm\.js/i.test(s.src)) || Array.isArray(window.dataLayer);
      const hasGoogleAds = scripts.some(s => /google(adservices|syndication)\.com/i.test(s.src)) || iframes.some(f => /google(adservices|syndication)\.com/i.test(f.src));
      const hasMetaPixel = typeof window.fbq === 'function' || scripts.some(s => /connect\.facebook\.net/i.test(s.src)) || iframes.some(f => /facebook\.com/i.test(f.src));
      const hasTikTokPixel = typeof window.ttq !== 'undefined' || scripts.some(s => /analytics\.tiktok\.com/i.test(s.src));
      const hasHotjar = typeof window.hj === 'function' || scripts.some(s => /(static|script)\.hotjar\.com/i.test(s.src));
      const hasCrazyEgg = typeof window.CE !== 'undefined' || scripts.some(s => /script\.crazyegg\.com/i.test(s.src));

      const dlEvents = Array.isArray(window.dataLayer) ? window.dataLayer.map(e => e && e.event).filter(Boolean) : [];
      return { hasGA4, hasUA, hasGTM, hasGoogleAds, hasMetaPixel, hasTikTokPixel, hasHotjar, hasCrazyEgg, dlEvents,
               scriptCount: scripts.length, iframeCount: iframes.length };
    });

    return {
      hasGA4: hasGA4_HIT || hasGA4_LIB || domBasedDetection.hasGA4,
      hasUA: hasUA_HIT || hasUA_LIB || domBasedDetection.hasUA,
      hasGTM: hasGTM_NET || domBasedDetection.hasGTM,
      hasGoogleAds: hasAds_HIT || domBasedDetection.hasGoogleAds,
      hasMetaPixel: hasMeta_HIT || hasMeta_LIB || domBasedDetection.hasMetaPixel,
      hasTikTokPixel: hasTikTok_HIT || domBasedDetection.hasTikTokPixel,
      hasHotjar: hasHotjar_HIT || domBasedDetection.hasHotjar,
      hasCrazyEgg: hasCrazyEgg_HIT || domBasedDetection.hasCrazyEgg,
      dlEvents: domBasedDetection.dlEvents,
      advanced: {
        networkDetection: {
          hasGA4_HIT, hasGA4_LIB, hasUA_HIT, hasUA_LIB, hasGTM: hasGTM_NET,
          hasAds_HIT, hasMeta_HIT, hasMeta_LIB, hasTikTok_HIT, hasHotjar_HIT, hasCrazyEgg_HIT
        },
        domDetection: domBasedDetection
      }
    };
  }

  analyzeConsentCompliance() {
    const defs = [
      ['Google Analytics 4', 'hasGA4'],
      ['Google Analytics Universal', 'hasUA'],
      ['Google Tag Manager', 'hasGTM'],
      ['Google Ads Tracking', 'hasGoogleAds'],
      ['Meta Pixel (Facebook/Instagram)', 'hasMetaPixel'],
      ['TikTok Pixel', 'hasTikTokPixel'],
      ['Hotjar', 'hasHotjar'],
      ['CrazyEgg', 'hasCrazyEgg']
    ];
    this.marketingTags = defs.map(([n,p]) => this.analyzeTagCompliance(n,p)).filter(t => t.relevant);
  }

  analyzeTagCompliance(tagName, tagProperty) {
    const { withoutConsent, withConsent, withReject } = this.results;

    if (tagProperty === 'hasGTM') {
      const presentNo = getLibPresent(withoutConsent, tagProperty);
      const presentYes = getLibPresent(withConsent, tagProperty);
      const presentRej = getLibPresent(withReject, tagProperty);
      if (!presentNo && !presentYes && !presentRej) return { relevant: false };

      const dlNo = lastDlEvents(withoutConsent);
      const hasConsentDefaultDenied = dlNo.some(e => typeof e === 'string' && e.toLowerCase().includes('consent'));

      const compliance = hasConsentDefaultDenied ? 'perfect' : 'inconsistent';
      const impact = hasConsentDefaultDenied
        ? '✅ GTM mit Consent-Initialisierung erkannt (standardmäßig „verweigert“ aktiviert).'
        : '🤔 GTM geladen, aber kein klarer Consent-Init-Event gefunden. Manuell prüfen, ob alle Tags Einwilligungs-Prüfungen haben.';
      const businessImpact = 'GTM Container vorhanden – Wirkung hängt von Einwilligungs-Prüfungen der einzelnen Tags ab.';
      return {
        relevant: true, name: tagName, property: tagProperty,
        withoutConsent: presentNo, withAccept: presentYes, withReject: presentRej,
        compliance, impact, gdprRisk: hasConsentDefaultDenied ? 'none' : 'medium', businessImpact
      };
    }

    const meta = TAG_META[tagProperty];
    if (!meta) return { relevant: false };

    const noHit  = getHit(withoutConsent, meta.hitKey);
    const yesHit = getHit(withConsent,   meta.hitKey);
    const rejHit = getHit(withReject,    meta.hitKey);

    const presentSomewhere =
      getLibPresent(withoutConsent, tagProperty) ||
      getLibPresent(withConsent,   tagProperty) ||
      getLibPresent(withReject,    tagProperty);

    if (!presentSomewhere && !noHit && !yesHit && !rejHit) return { relevant: false };

    const cspBlockedNo  = cspBlockedForDomains(withoutConsent, meta.domains);
    const cspBlockedRej = cspBlockedForDomains(withReject, meta.domains);

    let compliance = 'unknown', impact = '', gdprRisk = 'low';

    if (!noHit && yesHit && !rejHit) {
      compliance = 'perfect'; impact = `✅ ${tagName} respektiert Einwilligung (Daten werden erst nach „Zustimmen“ gesendet).`; gdprRisk = 'none';
    } else if (rejHit) {
      compliance = noHit ? 'inconsistent' : 'bad';
      impact = noHit
        ? `🤔 ${tagName} sendet Daten nach „Ablehnen“, aber nicht vor Einwilligung. Konfigurationsfehler vermutet.`
        : `🚨 ${tagName} sendet Daten trotz „Ablehnen“.`;
      gdprRisk = noHit ? 'medium' : 'high';
    } else if (noHit && !rejHit) {
      compliance = yesHit ? 'good' : 'inconsistent';
      impact = yesHit
        ? `🟡 ${tagName} sendet Daten schon ohne Einwilligung, stoppt aber bei „Ablehnen“.`
        : `🤔 ${tagName} sendet Daten ohne Einwilligung, aber nicht nach „Zustimmen“. Setup prüfen.`;
      gdprRisk = 'low';
    } else if (!noHit && !yesHit && !rejHit) {
      if (cspBlockedNo || cspBlockedRej) {
        compliance = 'inconsistent'; impact = `🟡 ${tagName} wirkt durch Sicherheitsregeln blockiert (keine Daten gesendet). Kein Einwilligungs-Verstoß, aber Messung wirkungslos.`; gdprRisk = 'none';
      } else {
        compliance = 'missing'; impact = `❌ ${tagName} ist eingebaut, aber es werden keine Daten gesendet. Einrichtung prüfen.`; gdprRisk = 'none';
      }
    } else {
      compliance = 'inconsistent'; impact = `🤔 ${tagName} zeigt ein uneinheitliches Muster. Manuelle Prüfung nötig.`; gdprRisk = 'medium';
    }

    return {
      relevant: true, name: tagName, property: tagProperty,
      withoutConsent: noHit, withAccept: yesHit, withReject: rejHit,
      compliance, impact, gdprRisk, businessImpact: this.getBusinessImpact(tagName, compliance),
      notes: { present: presentSomewhere, cspBlockedNo, cspBlockedRej }
    };
  }

  /* ------------------------- Evidence / Quellenaufbau ------------------------ */
  attachEvidence(scannedUrl) {
    const modes = [
      { key: 'withoutConsent', label: 'Ohne Consent' },
      { key: 'withConsent',    label: 'Mit Accept'   },
      { key: 'withReject',     label: 'Mit Reject'   }
    ];

    const evidence = {};

    const sampleRequests = (reqs = [], regex) =>
      reqs.filter(r => regex.test(r.url)).slice(0, 5).map(r => ({ url: r.url, status: r.status, ts: r.ts }));

    for (const [prop, meta] of Object.entries(TAG_META)) {
      const name = meta.label;
      const perMode = {};
      for (const m of modes) {
        const run = this.results[m.key];
        if (!run) continue;

        const hits = sampleRequests(run.requestLog || [], meta.hitRegex);
        const addedCookies = cookieDiff(run.cookiesBefore, run.cookiesAfter);
        const trackingCookies = highlightCookies(addedCookies);
        const cspBlocks = (run.cspViolations || [])
          .filter(v => meta.domains.some(d => (v?.message || '').includes(d) || (v?.violation?.blockedURI || '').includes(d)))
          .slice(0, 5)
          .map(v => ({ message: v.message, directive: v?.violation?.violatedDirective || '', blocked: v?.violation?.blockedURI || '' }));

        perMode[m.key] = {
          hits, trackingCookies, cspBlocks,
          dlEvents: lastDlEvents(run).slice(-5)
        };
      }

      evidence[prop] = {
        name,
        modes: perMode,
        howToVerify: [
          'DevTools öffnen → Network → Filter je nach Tool (z. B. "g/collect", "tr?id=")',
          'Seite neu laden (je Modus: ohne Einwilligung / Zustimmen / Ablehnen)',
          'Prüfen: erscheinen Anfragen? Status 200/204? Werden Browser-Einträge (Cookies) gesetzt?',
          'Konsole prüfen: wurden Verbindungen durch Sicherheitsregeln verhindert?'
        ],
        nonTechMeaning: this.nonTechMeaningText(name),
        nonTechFix: this.nonTechFixText(name)
      };
    }

    const gtmProp = 'hasGTM';
    const gtmPerMode = {};
    for (const m of modes) {
      const run = this.results[m.key];
      if (!run) continue;
      const cspBlocks = (run.cspViolations || [])
        .filter(v => (v?.message || '').includes('googletagmanager.com'))
        .slice(0, 5)
        .map(v => ({ message: v.message, directive: v?.violation?.violatedDirective || '', blocked: v?.violation?.blockedURI || '' }));
      gtmPerMode[m.key] = {
        hits: [],
        trackingCookies: highlightCookies(cookieDiff(run.cookiesBefore, run.cookiesAfter)),
        cspBlocks,
        dlEvents: lastDlEvents(run).slice(-5)
      };
    }
    evidence[gtmProp] = {
      name: 'Google Tag Manager',
      modes: gtmPerMode,
      howToVerify: [
        'DevTools → Sources → prüfen, ob gtm.js geladen wird',
        'Konsole: `window.dataLayer?.slice(-10)` → Einwilligungs-Events sichtbar?',
        'GTM-Preview nutzen: haben Tags Einwilligungs-Prüfungen?'
      ],
      nonTechMeaning: 'GTM ist der Container für Marketing-Tags. Er selbst misst nicht, steuert aber, wann andere Tools senden dürfen.',
      nonTechFix: 'Sicherstellen, dass in GTM Einwilligungs-Prüfungen aktiv sind und ein Einwilligungs-Initialisierungstag („standardmäßig verweigert“) vor allen Tags läuft.'
    };

    this.evidence = {
      url: scannedUrl,
      generatedAt: new Date().toISOString(),
      evidence
    };
  }

  nonTechMeaningText(name) {
    const map = {
      'Google Analytics 4': 'Misst Besucher & Seitenaufrufe. Ohne Einwilligung dürfen keine Mess-Anfragen gesendet werden.',
      'Google Analytics (UA)': 'Ältere GA-Version. Gleiches Prinzip: ohne Einwilligung keine Mess-Anfragen.',
      'Google Ads': 'Misst Anzeigen-Erfolge (Conversions). Ohne Einwilligung keine Conversion-Anfragen.',
      'Meta Pixel': 'Misst Facebook/Instagram-Kampagnen. Ohne Einwilligung keine Pixel-Anfragen/Retargeting.',
      'TikTok Pixel': 'Misst TikTok-Kampagnen. Ohne Einwilligung keine Pixel-Anfragen.',
      'Hotjar': 'Aufzeichnungen/Heatmaps. Ohne Einwilligung keine Tracking-Anfragen.',
      'CrazyEgg': 'Heatmaps/Scrollmaps. Ohne Einwilligung keine Tracking-Anfragen.'
    };
    return map[name] || 'Marketing-/Analyse-Tool. Ohne Einwilligung dürfen keine Tracking-Anfragen gesendet werden.';
  }

  nonTechFixText(name) {
    const map = {
      'Google Analytics 4': 'Im Tag Manager/CMP sicherstellen: Consent Mode v2 aktiv, `analytics_storage` vor Einwilligung = „verweigert“. GA4-Tag nur bei Einwilligung auslösen.',
      'Google Analytics (UA)': 'UA ist veraltet. Besser GA4 verwenden. Bis dahin: Tag nur bei Einwilligung auslösen.',
      'Google Ads': 'Conversion-Tags nur bei Einwilligung auslösen. Consent Mode v2 anwenden (ad_storage=„verweigert“ vor Einwilligung).',
      'Meta Pixel': 'Pixel über GTM mit Einwilligungs-Regel ausspielen (nicht hart im HTML). Falls rechtlich gewünscht, durch Sicherheitsregeln blockierte Domains freigeben.',
      'TikTok Pixel': 'Nur bei Einwilligung auslösen. In GTM Einwilligungs-Prüfung setzen.',
      'Hotjar': 'Nur bei Einwilligung laden. In GTM/CMP verknüpfen.',
      'CrazyEgg': 'Nur bei Einwilligung laden. In GTM/CMP verknüpfen.'
    };
    return map[name] || 'Über GTM/CMP so konfigurieren, dass das Tool nur nach Einwilligung sendet (und bei „Ablehnen“ sicher nicht).';
  }

  /* -------------------------------- Business etc. --------------------------- */
  getBusinessImpact(tagName, compliance) {
    const impacts = {
      'Google Analytics 4': {
        perfect: 'Besucherdaten werden DSGVO-konform erfasst',
        good: 'Tracking läuft, aber rechtliches Risiko',
        bad: 'Abmahnrisiko durch Missachtung der Einwilligung',
        missing: 'Keine Besucherdaten → Marketing fliegt blind',
        inconsistent: 'Messung inkonsistent – Datenqualität fraglich'
      },
      'Google Ads Tracking': {
        perfect: 'Conversion-Tracking DSGVO-konform',
        good: 'ROI messbar, aber rechtliches Risiko',
        bad: 'Abmahnrisiko + ungenaue Kampagnen-Daten',
        missing: 'Werbebudget-Verschwendung durch fehlende Messung',
        inconsistent: 'Conversions inkonsistent – Optimierung leidet'
      },
      'Meta Pixel (Facebook/Instagram)': {
        perfect: 'Social-ROI DSGVO-konform messbar',
        good: 'Retargeting funktioniert, rechtliches Risiko',
        bad: 'Abmahnrisiko bei Social Ads',
        missing: 'Facebook/Instagram Ads laufen blind',
        inconsistent: 'Events inkonsistent – Zielgruppenaufbau gestört'
      }
    };
    return impacts[tagName]?.[compliance] || 'Unbekannter Business-Impact';
  }

  classifyErrorPriority(message) {
    if (/CSP|security|blocked|failed/i.test(message)) return 'high';
    if (/googleadservices|connect\.facebook\.net|googletagmanager|analytics\.tiktok/i.test(message)) return 'high';
    if (/warning|deprecated/i.test(message)) return 'medium';
    return 'low';
  }
  classifyNetworkPriority(url) {
    if (/googleadservices|connect\.facebook\.net|googletagmanager|analytics\.tiktok/i.test(url)) return 'high';
    if (/tracking|analytics|pixel/i.test(url)) return 'medium';
    return 'low';
  }
  translateError(errorMessage) {
    const m = {
      'net::ERR_BLOCKED_BY_CLIENT': '🚫 Werbe-Blocker verhindert Messung – Umsatzeinbußen möglich',
      'Content Security Policy': '🔒 Sicherheitsregeln der Website verhindern wichtige Verbindungen',
      'googleadservices': '🎯 Google Ads-Messung verhindert – ROI nicht messbar',
      'connect.facebook.net': '📱 Meta Pixel verhindert – Social-ROI unbekannt',
      'googletagmanager': '📊 Google Tag Manager verhindert – alle Marketing-Tags betroffen',
      'analytics.tiktok.com': '🎵 TikTok Pixel verhindert – TikTok-ROI unbekannt',
      'static.hotjar.com': '🖱️ Hotjar verhindert – Nutzerverhalten nicht messbar',
      'script.hotjar.com': '🖱️ Hotjar verhindert – Nutzerverhalten nicht messbar',
      'CORS': '🌐 Fremd-Ressource nicht freigegeben (CORS-Problem)',
      'ERR_NAME_NOT_RESOLVED': '🌐 DNS-Problem – Dienst nicht erreichbar',
      'ERR_INTERNET_DISCONNECTED': '📡 Internetverbindung unterbrochen'
    };
    for (const [k,v] of Object.entries(m)) if (errorMessage.includes(k)) return v;
    return '⚠️ Technischer Fehler gefunden – kann die Messung beeinträchtigen';
  }
  translateNetworkIssue(url, status) {
    if (url.includes('googleadservices') || url.includes('googlesyndication')) return `🎯 Google Ads (${status}) – Conversion-Messung gestört`;
    if (url.includes('facebook.net') || url.includes('facebook.com') || url.includes('meta')) return `📱 Meta Pixel (${status}) – Social-ROI unbekannt`;
    if (url.includes('analytics') && url.includes('google')) return `📊 Google Analytics (${status}) – Besucherdaten fehlen`;
    if (url.includes('tiktok')) return `🎵 TikTok Pixel (${status}) – Kampagnen unoptimiert`;
    if (url.includes('hotjar')) return `🖱️ Hotjar (${status}) – Verhaltensanalyse nicht möglich`;
    return `⚠️ Dienst blockiert (${status}) – Auswirkung unklar`;
  }
  suggestFix(errorMessage) {
    if (errorMessage.includes('googleadservices')) return `Sicherheitsregeln erweitern:\nContent-Security-Policy:\n  script-src ... https://www.googleadservices.com;\n  connect-src ... https://www.googleadservices.com;`;
    if (errorMessage.includes('connect.facebook.net')) return `Sicherheitsregeln erweitern:\nContent-Security-Policy:\n  script-src ... https://connect.facebook.net;\n  connect-src ... https://connect.facebook.net;`;
    if (errorMessage.includes('googletagmanager')) return `Sicherheitsregeln erweitern:\nContent-Security-Policy:\n  script-src ... https://www.googletagmanager.com;\n  connect-src ... https://www.googletagmanager.com;`;
    if (errorMessage.includes('static.hotjar.com') || errorMessage.includes('script.hotjar.com')) return `Sicherheitsregeln erweitern:\nContent-Security-Policy:\n  script-src ... https://static.hotjar.com https://script.hotjar.com;\n  connect-src ... https://*.hotjar.com wss://*.hotjar.com;`;
    if (errorMessage.includes('Content Security Policy')) return 'CSP-Header prüfen und nötige Dienst-Domains in script-src und connect-src erlauben';
    return 'Fehlerquelle in der Browser-Konsole prüfen und betroffene Datei reparieren';
  }
  suggestFixForUrl(url, error) {
    try {
      const domain = new URL(url).hostname;
      if (error?.includes('CSP') || /BLOCKED/i.test(error || '')) return `Sicherheitsregeln (CSP) erweitern:\nContent-Security-Policy:\n  script-src ... https://${domain};\n  connect-src ... https://${domain};`;
      if (error?.includes('CORS')) return `CORS-Header vom Server ${domain} konfigurieren:\nAccess-Control-Allow-Origin: ${new URL(url).origin}`;
      if (error?.includes('DNS') || error?.includes('NAME_NOT_RESOLVED')) return `DNS-Konfiguration prüfen: nslookup ${domain}`;
      return `Erreichbarkeit von ${domain} prüfen: curl -I https://${domain}`;
    } catch { return 'URL-Format prüfen und Server-Konnektivität testen'; }
  }
  suggestCSPFix(violation) {
    try { const domain = new URL(violation.blockedURI).hostname; const directive = violation.violatedDirective; return `Sicherheitsregel anpassen:\nContent-Security-Policy:\n  ${directive} ... https://${domain};`; }
    catch { return `CSP-Regel prüfen: ${violation.violatedDirective} für ${violation.blockedURI}`; }
  }

  /* ------------------------------- API payload ------------------------------ */
  getComprehensiveResults(url) {
    const allErrors = [
      ...(this.results.withoutConsent?.errors || []),
      ...(this.results.withConsent?.errors || []),
      ...(this.results.withReject?.errors || [])
    ];
    const allNetworkIssues = [
      ...(this.results.withoutConsent?.networkIssues || []),
      ...(this.results.withConsent?.networkIssues || []),
      ...(this.results.withReject?.networkIssues || [])
    ];
    const allCSPViolations = [
      ...(this.results.withoutConsent?.cspViolations || []),
      ...(this.results.withConsent?.cspViolations || []),
      ...(this.results.withReject?.cspViolations || [])
    ];
    const totalIssues = allErrors.length + allNetworkIssues.length + allCSPViolations.length;
    const highPriorityIssues = [...allErrors, ...allNetworkIssues, ...allCSPViolations].filter(i => i.priority === 'high' || i.priority === 'critical').length;

    return {
      version: VERSION,
      scannedUrl: url,
      timestamp: new Date().toLocaleString('de-DE'),
      summary: {
        totalIssues,
        highPriorityIssues,
        marketingTags: this.marketingTags,
        consentCompliance: {
          withoutConsent: this.results.withoutConsent?.marketingTags || {},
          withConsent: this.results.withConsent?.marketingTags || {},
          withReject: this.results.withReject?.marketingTags || {}
        }
      },
      details: {
        errors: allErrors,
        networkIssues: allNetworkIssues,
        cspViolations: allCSPViolations
      },
      evidence: this.evidence || null,
      rawResults: this.results
    };
  }
}

const scanner = new UltimateWebsiteScanner();

/* --------------------------------- Endpoints -------------------------------- */
app.post('/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing URL' });
  try {
    console.log(`Starting scan for: ${url}`);
    const results = await scanner.scanWithRetry(url);

    // Save scan to database
    try {
      const scanId = saveScan(url, results);
      results.scanId = scanId;
      console.log(`Scan saved with ID: ${scanId}`);
    } catch (dbError) {
      console.error('Failed to save scan:', dbError);
      // Continue even if save fails
    }

    res.json(results);
  } catch (error) {
    console.error('Scan failed:', error);
    res.status(500).json({ error: 'Scan failed', details: error.message, timestamp: new Date().toISOString() });
  }
});

// Manager-Report im Klartext (nutzt deine bestehenden Module)
app.post('/scan-v2', async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'Missing URL' });

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1366, height: 900 }, ignoreHTTPSErrors: true });
  const page = await context.newPage();

  const findings = [];
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 });
    const s1 = await collectAllForCurrentState(page, context, { sessionLabel: 'ohne-consent' });
    findings.push(...s1.findings);

    await page.reload({ waitUntil: 'domcontentloaded', timeout: 45000 });
    const s2 = await collectAllForCurrentState(page, context, { sessionLabel: 'accept' });
    findings.push(...s2.findings);

    await page.reload({ waitUntil: 'domcontentloaded', timeout: 45000 });
    const s3 = await collectAllForCurrentState(page, context, { sessionLabel: 'reject' });
    findings.push(...s3.findings);

    const report = findings.map(f => formatReport(f));

    res.json({
      ok: true,
      scannedUrl: url,
      sessions: ['ohne-consent', 'accept', 'reject'],
      totalFindings: findings.length,
      report
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  } finally {
    await browser.close();
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: VERSION, timestamp: new Date().toISOString(), uptime: process.uptime() });
});
app.get('/version', (req, res) => {
  res.json({ version: VERSION, buildTime: new Date().toISOString(), nodeVersion: process.version });
});

// NEW ENDPOINTS - History, Compare, PDF

app.get('/api/history', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const history = getScanHistory(limit);
    res.json({ ok: true, history });
  } catch (error) {
    console.error('History fetch failed:', error);
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/history/:url', (req, res) => {
  try {
    const url = decodeURIComponent(req.params.url);
    const limit = parseInt(req.query.limit) || 10;
    const scans = getScansByUrl(url, limit);
    res.json({ ok: true, url, scans });
  } catch (error) {
    console.error('URL history fetch failed:', error);
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/scan/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const scan = getScanById(id);
    if (!scan) {
      return res.status(404).json({ ok: false, error: 'Scan not found' });
    }
    res.json({ ok: true, scan });
  } catch (error) {
    console.error('Scan fetch failed:', error);
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/compare/:id1/:id2', (req, res) => {
  try {
    const id1 = parseInt(req.params.id1);
    const id2 = parseInt(req.params.id2);
    const comparison = compareScans(id1, id2);
    res.json({ ok: true, comparison });
  } catch (error) {
    console.error('Comparison failed:', error);
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/stats', (req, res) => {
  try {
    const stats = getStats();
    res.json({ ok: true, stats });
  } catch (error) {
    console.error('Stats fetch failed:', error);
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/scan/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    deleteScan(id);
    res.json({ ok: true, message: 'Scan deleted' });
  } catch (error) {
    console.error('Scan deletion failed:', error);
    res.status(500).json({ ok: false, error: error.message });
  }
});

// PDF Export
app.post('/api/export/pdf', async (req, res) => {
  try {
    const { scanId } = req.body;
    let scanData;

    if (scanId) {
      const scan = getScanById(scanId);
      if (!scan) {
        return res.status(404).json({ ok: false, error: 'Scan not found' });
      }
      scanData = scan.scan_data;
    } else {
      scanData = req.body.scanData;
      if (!scanData) {
        return res.status(400).json({ ok: false, error: 'No scan data provided' });
      }
    }

    const pdfBuffer = await generatePDF(scanData);

    const filename = `website-scan-${scanData.scannedUrl?.replace(/[^a-z0-9]/gi, '-') || 'report'}-${Date.now()}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.send(pdfBuffer);
  } catch (error) {
    console.error('PDF generation failed:', error);
    res.status(500).json({ ok: false, error: error.message });
  }
});

/* ------------------------- Playwright Browser Check ------------------------ */
async function checkPlaywrightBrowsers() {
  console.log('\n🔍 Checking Playwright browser installation...');
  console.log(`📁 PLAYWRIGHT_BROWSERS_PATH: ${process.env.PLAYWRIGHT_BROWSERS_PATH}`);
  console.log(`📁 Current directory: ${__dirname}`);

  try {
    // List browser cache directory
    if (fs.existsSync(BROWSER_PATH)) {
      const contents = fs.readdirSync(BROWSER_PATH);
      console.log(`📦 Browser cache contents (${contents.length} items):`, contents);

      // Look for chromium directories
      const chromiumDirs = contents.filter(d => d.includes('chromium'));
      if (chromiumDirs.length > 0) {
        console.log(`🔍 Found Chromium directories:`, chromiumDirs);
        chromiumDirs.forEach(dir => {
          const dirPath = path.join(BROWSER_PATH, dir);
          if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
            console.log(`   ${dir}:`, fs.readdirSync(dirPath));
          }
        });
      }
    } else {
      console.log(`⚠️  Browser cache directory does not exist: ${BROWSER_PATH}`);
      console.log('📁 Creating directory...');
      fs.mkdirSync(BROWSER_PATH, { recursive: true });
    }

    // Try to launch a browser to verify it works
    console.log('🧪 Testing browser launch...');
    const testBrowser = await chromium.launch({
      headless: true,
      timeout: 10000
    });
    await testBrowser.close();
    console.log('✅ Playwright browsers are installed and working!\n');
    return true;
  } catch (error) {
    console.error('❌ Playwright browser check failed:', error.message);
    console.log('\n🔧 Attempting to install browsers at runtime...');
    console.log(`🎯 Installing to: ${BROWSER_PATH}`);

    try {
      // Install browsers at runtime
      console.log('Running: npx playwright install chromium');
      execSync('npx playwright install chromium', {
        stdio: 'inherit',
        timeout: 180000, // 3 minutes timeout
        env: { ...process.env, PLAYWRIGHT_BROWSERS_PATH: BROWSER_PATH }
      });

      // Verify installation
      console.log('\n🧪 Re-testing browser launch...');
      const testBrowser = await chromium.launch({
        headless: true,
        timeout: 10000
      });
      await testBrowser.close();
      console.log('✅ Browser installation successful!\n');
      return true;
    } catch (installError) {
      console.error('❌ Failed to install browsers at runtime:', installError.message);
      console.error('⚠️  Scanner will not work until browsers are properly installed!');
      return false;
    }
  }
}

/* ----------------------------- Start & Shutdown ---------------------------- */
const server = app.listen(PORT, async () => {
  console.log(`🚀 Website Scanner running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔍 Scanner UI:   http://localhost:${PORT}/`);

  // Check Playwright browsers after server starts
  await checkPlaywrightBrowsers();
});
const graceful = (sig) => async () => {
  console.log(`\nReceived ${sig}, shutting down gracefully...`);
  server.close(() => { console.log('HTTP server closed.'); process.exit(0); });
  setTimeout(() => { console.warn('Force exit after 5s'); process.exit(1); }, 5000).unref();
};
process.on('SIGINT', graceful('SIGINT'));
process.on('SIGTERM', graceful('SIGTERM'));

