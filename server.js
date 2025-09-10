import express from 'express';
import { chromium } from 'playwright';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import { collectAllForCurrentState } from './ScannerModules.js';
import { formatReport } from './ReportFormatter.js';

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

/* -------------------- Marketing-Tag Metadaten & Cookie-Hinweise -------------- */
/*  Sprache für Laien:
    - "HIT" nennen wir in der Darstellung "Datenübertragung"
    - "Beispiel-Requests" -> "Nachweis im Browser (Network)"
    - "CSP-Blockaden" -> "Sicherheitsregeln haben Verbindungen verhindert"
    - "Neu gesetzte Cookies" -> "Neue Einträge im Browser-Speicher"
*/
const TAG_META = {
  hasGA4:        { hitKey: 'hasGA4_HIT',        label: 'Google Analytics 4',                 hitRegex: /(www|region\d+)\.google-analytics\.com\/g\/collect/i,      domains: ['google-analytics.com', 'g.doubleclick.net'] },
  hasUA:         { hitKey: 'hasUA_HIT',         label: 'Google Analytics (UA)',              hitRegex: /google-analytics\.com\/collect(\?|$)/i,                      domains: ['google-analytics.com'] },
  hasGoogleAds:  { hitKey: 'hasAds_HIT',        label: 'Google Ads',                         hitRegex: /(googleadservices|googlesyndication)\.com/i,                domains: ['googleadservices.com','googlesyndication.com'] },
  hasMetaPixel:  { hitKey: 'hasMeta_HIT',       label: 'Meta Pixel (Facebook/Instagram)',    hitRegex: /(facebook\.com\/tr|connect\.facebook\.net)/i,               domains: ['facebook.com','connect.facebook.net'] },
  hasTikTokPixel:{ hitKey: 'hasTikTok_HIT',     label: 'TikTok Pixel',                       hitRegex: /analytics\.tiktok\.com/i,                                   domains: ['analytics.tiktok.com'] },
  hasHotjar:     { hitKey: 'hasHotjar_HIT',     label: 'Hotjar',                             hitRegex: /(static|script)\.hotjar\.com/i,                             domains: ['static.hotjar.com','script.hotjar.com'] },
  hasCrazyEgg:   { hitKey: 'hasCrazyEgg_HIT',   label: 'CrazyEgg',                           hitRegex: /script\.crazyegg\.com/i,                                    domains: ['script.crazyegg.com'] },
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

    const browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage','--disable-web-security','--disable-features=VizDisplayCompositor']
    });

    try {
      console.log('🚫 Run A: Scanning without consent (default denied)...');
      this.results.withoutConsent = await this.runSingleScan(browser, url, 'no-consent');

      console.log('✅ Run B: Scanning with consent accepted...');
      this.results.withConsent = await this.runSingleScan(browser, url, 'accept');

      console.log('❌ Run C: Scanning with consent rejected...');
      this.results.withReject = await this.runSingleScan(browser, url, 'reject');

      this.analyzeConsentCompliance();
      this.attachEvidence(url);
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
        translation: 'Auf der Seite ist ein Fehler aufgetreten.',
        techFix: 'Die IT soll die Fehlermeldung in der Browser-Konsole prüfen und beheben.',
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
        translation: 'Die Sicherheits­einstellungen der Website lassen diese Verbindung nicht zu.',
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
        translation: 'Website nicht erreichbar.',
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
      ['Google Ads', 'hasGoogleAds'],
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
        ? '✅ GTM beachtet die Einwilligung: Standard ist „abgelehnt“, bis aktiv zugestimmt wird.'
        : '🤔 GTM geladen, aber kein klarer Einwilligungs-Start sichtbar. Prüfen, ob alle Tags Einwilligungs-Prüfungen haben.';
      const businessImpact = 'GTM ist der Container. Wirkung hängt davon ab, ob die einzelnen Tags eine Einwilligung respektieren.';
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
      compliance = 'perfect';
      impact = `✅ ${tagName} respektiert die Einwilligung (Daten werden erst nach „Zustimmen“ gesendet).`;
      gdprRisk = 'none';
    } else if (rejHit) {
      compliance = noHit ? 'inconsistent' : 'bad';
      impact = noHit
        ? `🤔 ${tagName} sendet Daten trotz „Ablehnen“, jedoch nicht vor der Einwilligung. Konfiguration prüfen.`
        : `🚨 ${tagName} sendet Daten trotz „Ablehnen“.`;
      gdprRisk = noHit ? 'medium' : 'high';
    } else if (noHit && !rejHit) {
      compliance = yesHit ? 'good' : 'inconsistent';
      impact = yesHit
        ? `🟡 ${tagName} sendet bereits vor Einwilligung, stoppt aber bei „Ablehnen“.`
        : `🤔 ${tagName} sendet vor Einwilligung, jedoch nicht nach „Zustimmen“. Konfiguration prüfen.`;
      gdprRisk = 'low';
    } else if (!noHit && !yesHit && !rejHit) {
      if (cspBlockedNo || cspBlockedRej) {
        compliance = 'inconsistent';
        impact = `🟡 ${tagName} wird durch Sicherheits­einstellungen blockiert. Es sind keine Datenübertragungen sichtbar.`;
        gdprRisk = 'none';
      } else {
        compliance = 'missing';
        impact = `❌ ${tagName} ist zwar eingebunden, aber es wurden keine Datenübertragungen erkannt.
Das bedeutet: Es kommen keine Besucherdaten an. Die IT/Agentur muss prüfen, ob die Einbindung korrekt ist (Tag Manager, Consent Mode, IDs).`;
        gdprRisk = 'none';
      }
    } else {
      compliance = 'inconsistent';
      impact = `🤔 ${tagName} zeigt ein uneinheitliches Verhalten beim Senden von Daten. Manuelle Prüfung nötig.`;
      gdprRisk = 'medium';
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
      { key: 'withoutConsent', label: 'Ohne Einwilligung' },
      { key: 'withConsent',    label: 'Mit Einwilligung'   },
      { key: 'withReject',     label: 'Bei Ablehnen'       }
    ];

    const evidence = {};

    // Hilfsfunktion: Beispiel-Requests je Tag & Modus
    const sampleRequests = (reqs = [], regex) =>
      reqs.filter(r => regex.test(r.url)).slice(0, 5).map(r => ({ url: r.url, status: r.status, ts: r.ts }));

    // Für jedes Tag Belege zusammenstellen
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
          'Browser-Werkzeuge öffnen → Tab „Network/Netzwerk“ → nach dem Dienst filtern (z. B. „g/collect“, „tr?id=“).',
          'Seite neu laden (je Modus: Ohne Einwilligung / Mit Einwilligung / Bei Ablehnen).',
          'Prüfen: Erscheinen Datenübertragungen? Status 200/204? Werden Einträge im Browser-Speicher gesetzt (_ga, _fbp …)?',
          'Tab „Konsole“ prüfen: Werden Verbindungen durch Sicherheitsregeln verhindert?'
        ],
        nonTechMeaning: this.nonTechMeaningText(name),
        nonTechFix: this.nonTechFixText(name)
      };
    }

    // GTM (ohne Hit-Regex): Belege aus dataLayer + CSP
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
        'DevTools → Sources → prüfen, ob gtm.js geladen wird.',
        'Konsole: `window.dataLayer?.slice(-10)` → Sind Einwilligungs-Events sichtbar?',
        'GTM-Preview nutzen: Haben Tags Einwilligungs-Prüfungen?'
      ],
      nonTechMeaning: 'GTM ist der Container für Marketing-Tags. Er selbst misst nicht, steuert aber, wann andere Tools auslösen.',
      nonTechFix: 'Sicherstellen, dass in GTM Einwilligungs-Prüfungen aktiv sind und ein Consent-Initialisierungstag („abgelehnt“ als Standard) vor allen Tags läuft.'
    };

    this.evidence = {
      url: scannedUrl,
      generatedAt: new Date().toISOString(),
      evidence
    };
  }

  nonTechMeaningText(name) {
    const map = {
      'Google Analytics 4': 'Misst Besucher & Seitenaufrufe. Ohne Einwilligung dürfen keine Daten an Google gesendet werden.',
      'Google Analytics (UA)': 'Ältere Google Analytics-Version. Gleiches Prinzip: ohne Einwilligung keine Datenübertragung.',
      'Google Ads': 'Misst Anzeigen-Erfolge (Conversions). Ohne Einwilligung keine Conversion-Daten.',
      'Meta Pixel (Facebook/Instagram)': 'Misst Facebook/Instagram-Kampagnen. Ohne Einwilligung keine Pixel-Daten/Retargeting.',
      'TikTok Pixel': 'Misst TikTok-Kampagnen. Ohne Einwilligung keine Pixel-Daten.',
      'Hotjar': 'Erstellt Aufzeichnungen/Heatmaps. Ohne Einwilligung keine Übertragung.',
      'CrazyEgg': 'Heatmaps/Scrollmaps. Ohne Einwilligung keine Übertragung.'
    };
    return map[name] || 'Marketing-/Analyse-Tool. Ohne Einwilligung dürfen keine Tracking-Daten gesendet werden.';
  }

  nonTechFixText(name) {
    const map = {
      'Google Analytics 4': 'Im Tag Manager/CMP sicherstellen: Consent Mode aktiv, „analytics_storage“ vor Einwilligung = „abgelehnt“. GA4-Tag nur nach Einwilligung auslösen.',
      'Google Analytics (UA)': 'UA ist veraltet. Besser GA4 verwenden. Bis dahin: Tag nur nach Einwilligung auslösen.',
      'Google Ads': 'Conversion-Tags nur nach Einwilligung auslösen. Consent Mode anwenden (ad_storage vor Einwilligung = „abgelehnt“).',
      'Meta Pixel (Facebook/Instagram)': 'Pixel über GTM mit Einwilligungs-Regel ausspielen. Nicht fest ins HTML einbauen. Falls Sicherheitsregeln blockieren, Domain erlauben (wenn rechtlich gewünscht).',
      'TikTok Pixel': 'Nur nach Einwilligung auslösen. In GTM Einwilligungs-Prüfung setzen.',
      'Hotjar': 'Nur nach Einwilligung laden. In GTM/CMP verknüpfen.',
      'CrazyEgg': 'Nur nach Einwilligung laden. In GTM/CMP verknüpfen.'
    };
    return map[name] || 'Über GTM/CMP so konfigurieren, dass das Tool nur nach Einwilligung auslöst (und bei „Ablehnen“ sicher nicht).';
  }

  /* -------------------------------- Business etc. --------------------------- */
  getBusinessImpact(tagName, compliance) {
    const impacts = {
      'Google Analytics 4': {
        perfect: 'Besucherdaten werden DSGVO-konform erfasst.',
        good: 'Tracking läuft, aber rechtliches Risiko.',
        bad: 'Rechtliches Risiko, weil Einwilligung ignoriert wird.',
        missing: 'Keine Besucherdaten → Marketing arbeitet im Blindflug.',
        inconsistent: 'Uneinheitliche Daten → Qualität fraglich.'
      },
      'Google Ads': {
        perfect: 'Conversion-Tracking DSGVO-konform.',
        good: 'ROI messbar, aber rechtliches Risiko.',
        bad: 'Rechtliches Risiko + ungenaue Kampagnen-Daten.',
        missing: 'Werbebudget ohne Messung → Verschwendung möglich.',
        inconsistent: 'Conversions werden uneinheitlich erfasst → Optimierung leidet.'
      },
      'Meta Pixel (Facebook/Instagram)': {
        perfect: 'Social ROI DSGVO-konform messbar.',
        good: 'Retargeting funktioniert, rechtliches Risiko.',
        bad: 'Rechtliches Risiko bei Facebook/Instagram Ads.',
        missing: 'Social Ads laufen ohne Messung.',
        inconsistent: 'Events uneinheitlich → Zielgruppenaufbau gestört.'
      }
    };
    return impacts[tagName]?.[compliance] || 'Business-Impact unklar';
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
      'net::ERR_BLOCKED_BY_CLIENT': 'Ein Browser-Blocker verhindert die Messung.',
      'Content Security Policy': 'Sicherheits­einstellungen blockieren wichtige Verbindungen.',
      'googleadservices': 'Google Ads Tracking blockiert.',
      'connect.facebook.net': 'Meta Pixel blockiert.',
      'googletagmanager': 'Tag Manager blockiert.',
      'analytics.tiktok.com': 'TikTok Pixel blockiert.',
      'static.hotjar.com': 'Hotjar blockiert.',
      'script.hotjar.com': 'Hotjar blockiert.',
      'CORS': 'Cross-Origin-Problem: externe Datei nicht ladbar.',
      'ERR_NAME_NOT_RESOLVED': 'DNS-Problem: Dienst nicht erreichbar.',
      'ERR_INTERNET_DISCONNECTED': 'Internetverbindung unterbrochen.'
    };
    for (const [k,v] of Object.entries(m)) if (errorMessage.includes(k)) return v;
    return 'Fehler, der Funktionen/Tracking beeinträchtigen kann.';
  }
  translateNetworkIssue(url, status) {
    if (url.includes('googleadservices') || url.includes('googlesyndication')) return `Google Ads (${status}) – Conversion-Tracking gestört.`;
    if (url.includes('facebook.net') || url.includes('facebook.com') || url.includes('meta')) return `Meta Pixel (${status}) – Social ROI unbekannt.`;
    if (url.includes('analytics') && url.includes('google')) return `Google Analytics (${status}) – Besucherdaten fehlen.`;
    if (url.includes('tiktok')) return `TikTok Pixel (${status}) – Kampagnen laufen unoptimiert.`;
    if (url.includes('hotjar')) return `Hotjar (${status}) – Nutzerverhalten nicht analysierbar.`;
    return `Externer Dienst (${status}) – Funktion möglicherweise eingeschränkt.`;
  }
  suggestFix(errorMessage) {
    if (errorMessage.includes('googleadservices')) return `Sicherheits­richtlinie erweitern (CSP):\nscript-src ... https://www.googleadservices.com;\nconnect-src ... https://www.googleadservices.com;`;
    if (errorMessage.includes('connect.facebook.net')) return `Sicherheits­richtlinie erweitern (CSP):\nscript-src ... https://connect.facebook.net;\nconnect-src ... https://connect.facebook.net;`;
    if (errorMessage.includes('googletagmanager')) return `Sicherheits­richtlinie erweitern (CSP):\nscript-src ... https://www.googletagmanager.com;\nconnect-src ... https://www.googletagmanager.com;`;
    if (errorMessage.includes('static.hotjar.com') || errorMessage.includes('script.hotjar.com')) return `Sicherheits­richtlinie erweitern (CSP):\nscript-src ... https://static.hotjar.com https://script.hotjar.com;\nconnect-src ... https://*.hotjar.com wss://*.hotjar.com;`;
    if (errorMessage.includes('Content Security Policy')) return 'CSP-Header prüfen und notwendige Domains in script-src/connect-src erlauben.';
    return 'Fehlermeldung in der Browser-Konsole prüfen und beheben.';
  }
  suggestFixForUrl(url, error) {
    try {
      const domain = new URL(url).hostname;
      if (error?.includes('CSP') || /BLOCKED/i.test(error || '')) return `Sicherheits­richtlinie (CSP) erweitern:\nscript-src ... https://${domain};\nconnect-src ... https://${domain};`;
      if (error?.includes('CORS')) return `CORS-Header vom Server ${domain} konfigurieren:\nAccess-Control-Allow-Origin: <Ihre Domain>`;
      if (error?.includes('DNS') || error?.includes('NAME_NOT_RESOLVED')) return `DNS-Konfiguration prüfen: nslookup ${domain}`;
      return `Server-Erreichbarkeit von ${domain} prüfen: curl -I https://${domain}`;
    } catch { return 'URL-Format prüfen und Server-Konnektivität testen'; }
  }
  suggestCSPFix(violation) {
    try { const domain = new URL(violation.blockedURI).hostname; const directive = violation.violatedDirective; return `Sicherheits­richtlinie (CSP) anpassen:\n${directive} ... https://${domain};`; }
    catch { return `CSP-Policy prüfen: ${violation.violatedDirective} für ${violation.blockedURI}`; }
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
    res.json(results);
  } catch (error) {
    console.error('Scan failed:', error);
    res.status(500).json({ error: 'Scan failed', details: error.message, timestamp: new Date().toISOString() });
  }
});

// Optional: Manager-Report im Klartext-Format (nutzt deine beiden Module)
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

/* ---------------------------------- Frontend -------------------------------- */
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ultimate Website Scanner - DSGVO & Marketing Check</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6;color:#333;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px}
.container{max-width:1200px;margin:0 auto;background:#fff;border-radius:16px;box-shadow:0 25px 50px rgba(0,0,0,.15);overflow:hidden}
.header{background:linear-gradient(135deg,#2d3748 0%,#1a202c 100%);color:#fff;padding:50px 30px;text-align:center}
.header h1{font-size:2.5em;margin-bottom:20px;font-weight:700;line-height:1.2}
.header p{opacity:.9;font-size:1.1em;margin-bottom:15px;max-width:800px;margin-left:auto;margin-right:auto}
.features{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:25px;padding:30px;background:rgba(255,255,255,.1);margin-top:30px;border-radius:12px}
.feature{text-align:center;padding:20px}.feature-icon{font-size:2.5em;margin-bottom:15px}.feature h3{margin-bottom:10px;font-size:1.2em}.feature p{font-size:.95em;opacity:.9}
.form-section{padding:50px}.input-group{margin-bottom:30px}label{display:block;margin-bottom:12px;font-weight:600;color:#2d3748;font-size:1.1em}
.url-input-container{position:relative}input[type="url"]{width:100%;padding:20px;border:2px solid #e2e8f0;border-radius:12px;font-size:16px;transition:all .3s;box-shadow:0 2px 4px rgba(0,0,0,.1)}
input[type="url"]:focus{border-color:#667eea;outline:none;box-shadow:0 0 0 3px rgba(102,126,234,.1)}input[type="url"].valid{border-color:#48bb78}input[type="url"].invalid{border-color:#f56565}
.url-validation{font-size:.85em;margin-top:8px;padding:5px 0;min-height:20px}.url-validation.valid{color:#48bb78}.url-validation.invalid{color:#f56565}
.scan-button{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;border:none;padding:22px 50px;border-radius:12px;font-size:18px;font-weight:600;cursor:pointer;width:100%;transition:all .3s;box-shadow:0 4px 15px rgba(102,126,234,.4);position:relative;overflow:hidden}
.scan-button:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 8px 25px rgba(102,126,234,.6)}.scan-button:disabled{opacity:.6;cursor:not-allowed;transform:none;box-shadow:0 4px 15px rgba(102,126,234,.2)}
.loading{display:none;text-align:center;padding:40px;color:#667eea;background:#f8f9fa;margin:20px;border-radius:12px}
.progress-container{margin:25px 0}.progress-bar{width:100%;height:8px;background:#e2e8f0;border-radius:4px;overflow:hidden;position:relative}.progress-fill{height:100%;background:linear-gradient(90deg,#667eea,#764ba2);width:0%;transition:width .5s ease;border-radius:4px;position:relative}
.results{display:none;padding:0 50px 50px}
.risk-indicator{padding:25px;border-radius:12px;margin-bottom:30px;font-weight:600;text-align:center;position:relative;overflow:hidden}
.risk-high{background:linear-gradient(135deg,#fed7d7 0%,#feb2b2 100%);color:#c53030;border:2px solid #fc8181}
.risk-medium{background:linear-gradient(135deg,#fefcbf 0%,#faf089 100%);color:#d69e2e;border:2px solid #f6e05e}
.risk-low{background:linear-gradient(135deg,#c6f6d5 0%,#9ae6b4 100%);color:#2f855a;border:2px solid #68d391}
.compliance-item{padding:20px;margin:15px 0;border-radius:10px;border-left:5px solid;position:relative;transition:all .3s}
.compliance-perfect{background:#f0fff4;border-left-color:#38a169}.compliance-good{background:#fefcbf;border-left-color:#d69e2e}.compliance-bad{background:#fff5f5;border-left-color:#e53e3e}.compliance-missing{background:#f7fafc;border-left-color:#a0aec0}.compliance-inconsistent{background:#fdf2e9;border-left-color:#ed8936}
.consent-matrix{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:15px;font-size:.9em;background:#f8f9fa;padding:15px;border-radius:8px}
.consent-result{text-align:center;padding:10px;border-radius:6px;font-weight:500}
.badge{display:inline-block;background:#2b6cb0;color:#fff;border-radius:999px;padding:3px 8px;font-size:.75rem;margin-left:8px}
.evidence{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:12px;margin-top:12px}
.evidence pre{background:#edf2f7;padding:10px;border-radius:8px;overflow:auto}
.evidence h4{margin:8px 0 6px 0}
.fix-suggestion{background:#e6fffa;border:1px solid #4fd1c7;padding:12px;border-radius:8px;margin-top:8px;font-family:Monaco,Menlo,monospace;font-size:.9em;position:relative}
.copy-button{position:absolute;top:8px;right:8px;background:#319795;color:#fff;border:none;padding:4px 8px;border-radius:4px;font-size:.8em;cursor:pointer}
@media (max-width:768px){.container{margin:10px}.form-section,.results{padding:30px 20px}.consent-matrix{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔍 Website-Scanner: DSGVO & Marketing Check</h1>
    <p>Finde heraus, ob deine Website rechtssicher funktioniert und wo du Umsatz verlierst.</p>
    <p style="font-size:.95em;opacity:.8;">Der 3-Session-Test prüft Cookie-Banner, Marketing-Tags und Sicherheits­einstellungen</p>
  </div>

  <div class="form-section">
    <form id="scanForm">
      <div class="input-group">
        <label for="url">Website-URL für vollständige Analyse:</label>
        <div class="url-input-container">
          <input type="url" id="url" placeholder="https://ihre-website.de" required>
          <div class="url-validation" id="urlValidation"></div>
        </div>
      </div>
      <button type="submit" class="scan-button" id="scanBtn">🔍 Vollständigen 3-Session-Scan starten</button>
    </form>

    <div class="loading" id="loading">
      <h3>⏳ Analyse läuft…</h3>
      <div class="progress-container"><div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div></div>
      <p id="loadingText">Initialisiere Browser…</p><p><small>Das kann 60–90 Sekunden dauern</small></p>
    </div>
  </div>

  <div class="results" id="results"></div>

  <div class="footer" style="text-align:center;padding:24px;background:#f8f9fa;color:#718096;font-size:.9em">
    Powered by ReguKit • Sichere Analyse ohne Datenspeicherung • Made in Germany
  </div>
</div>

<script>
(function(){
  const scanForm = document.getElementById('scanForm');
  const urlInput = document.getElementById('url');
  const scanBtn = document.getElementById('scanBtn');
  const loadingDiv = document.getElementById('loading');
  const resultsDiv = document.getElementById('results');
  const progressFill = document.getElementById('progressFill');
  const loadingText = document.getElementById('loadingText');
  const urlValidation = document.getElementById('urlValidation');

  const steps = ['Initialisiere Browser…','Scanne ohne Einwilligung…','Scanne mit Einwilligung…','Scanne bei Ablehnen…','Analysiere Ergebnisse…','Generiere Report…'];
  let currentStep = 0, progressInterval;

  urlInput.addEventListener('input', e => {
    const url = e.target.value.trim();
    const ok = validateUrl(url);
    urlValidation.textContent = url === '' ? '' : (ok ? 'Gültige URL ✔️' : 'Ungültige URL. Muss mit http:// oder https:// beginnen.');
    urlValidation.className = 'url-validation ' + (ok ? 'valid' : 'invalid');
    urlInput.className = ok ? 'valid' : 'invalid';
    scanBtn.disabled = !ok;
  });
  function validateUrl(u){ try{ const x=new URL(u); return x.protocol==='http:'||x.protocol==='https:'; } catch(e){ return false; } }
  function advance(){ if(currentStep<steps.length){ loadingText.textContent=steps[currentStep]; progressFill.style.width=((currentStep/steps.length)*100)+'%'; currentStep++; } else { clearInterval(progressInterval); progressFill.style.width='100%'; } }

  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!validateUrl(url)) return alert('Bitte eine gültige URL eingeben.');

    scanBtn.disabled = true; loadingDiv.style.display='block'; resultsDiv.style.display='none'; resultsDiv.innerHTML='';
    currentStep=0; advance(); progressInterval=setInterval(advance,15000);

    try{
      const resp = await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
      clearInterval(progressInterval); progressFill.style.width='100%'; loadingText.textContent='Report fertiggestellt! 🎉';
      const data = await resp.json(); if(!resp.ok) throw new Error(data.details||'Unknown error');
      setTimeout(()=>{ renderResults(data); loadingDiv.style.display='none'; resultsDiv.style.display='block'; scanBtn.disabled=false; }, 800);
    }catch(err){
      clearInterval(progressInterval); loadingDiv.style.display='none'; scanBtn.disabled=false;
      alert('Scan failed: '+err.message); console.error(err);
    }
  });

  function renderResults(data){
    let html = '';
    const countIssues = data.details.errors.length + data.details.networkIssues.length + data.details.cspViolations.length;
    const riskLevel = data.summary.highPriorityIssues>0?'high':(countIssues>0?'medium':'low');
    const riskText  = data.summary.highPriorityIssues>0?'Hohes Risiko 🚨':(countIssues>0?'Mittleres Risiko 🟡':'Niedriges Risiko ✅');
    html += \`<div class="risk-indicator risk-\${riskLevel}"><h2>\${riskText}</h2><p>Gefundene Probleme: \${countIssues} (davon \${data.summary.highPriorityIssues} kritisch)</p></div>\`;

    html += '<h2>Marketing & DSGVO Compliance</h2>';
    data.summary.marketingTags.forEach(tag => {
      html += renderCompliance(tag, data.evidence?.evidence || {});
    });

    html += \`<h2>Fehler & Blockaden (Konsole · Netzwerk · Sicherheitsregeln) — \${countIssues} gefunden</h2>\`;
    html += renderErrors(data.details.errors);
    html += renderIssues(data.details.networkIssues);
    html += renderCSP(data.details.cspViolations);

    resultsDiv.innerHTML = html;
  }

  function renderCompliance(tag, evMap){
    const ev = evMap[tag.property] || null;

    const badgeMap = {
      perfect: '✅ Einwilligung wird korrekt beachtet',
      good: '🟡 Eingeschränkt korrekt',
      bad: '❌ Einwilligung wird missachtet',
      missing: '❌ Nicht aktiv / keine Daten',
      inconsistent: '🤔 Uneinheitliches Verhalten'
    };
    const badge = badgeMap[tag.compliance] || 'Hinweis';

    let humanTitle = tag.name || 'Tool';
    let humanImpact = (tag.impact || 'Hinweis zur Einbindung.').replace(/HITs?/ig,'Datenübertragungen');
    if (/Google Analytics 4/i.test(humanTitle) && /keine Datenübertragungen/i.test(humanImpact) === false && /keine/i.test(humanImpact)) {
      humanImpact = 'Es wurden keine Besucherdaten an Google Analytics 4 gesendet.';
    }

    return \`
      <div class="compliance-item compliance-\${tag.compliance}">
        <h3>\${humanTitle} <span class="badge">\${badge}</span></h3>
        <p>\${humanImpact}</p>

        <div class="consent-matrix">
          <div class="consent-result \${tag.withoutConsent ? 'consent-fail' : 'consent-pass'}">Ohne Einwilligung: \${tag.withoutConsent ? 'Daten gesendet' : 'Keine Daten gesendet'}</div>
          <div class="consent-result \${tag.withAccept ? 'consent-pass' : 'consent-fail'}">Mit Einwilligung: \${tag.withAccept ? 'Daten gesendet' : 'Keine Daten gesendet'}</div>
          <div class="consent-result \${tag.withReject ? 'consent-fail' : 'consent-pass'}">Bei Ablehnen: \${tag.withReject ? 'Daten gesendet' : 'Keine Daten gesendet'}</div>
        </div>

        \${renderEvidence(ev)}

        <div class="evidence">
          <h4>Warum das wichtig ist</h4>
          <p>\${ev?.nonTechMeaning || 'Ohne diese Daten können Besucherzahlen und Kampagnenerfolge nicht ausgewertet werden.'}</p>

          <h4>Was die IT/Agentur jetzt tun soll</h4>
          <div class="fix-suggestion">
            <code>\${ev?.nonTechFix || 'Im Tag Manager/CMP sicherstellen, dass das Tool nur nach Einwilligung auslöst.'}</code>
            <button class="copy-button" onclick="navigator.clipboard.writeText(this.previousSibling.textContent)">Copy</button>
          </div>
        </div>
      </div>
    \`;
  }

  function renderEvidence(ev){
    if(!ev) return '';
    const m = ev.modes || {};
    const block = (label,key) => {
      const x = m[key] || {};
      const hitList = (x.hits||[]).map(h => \`• \${h.url} (\${h.status||0})\`).join('<br>') || '– keine Datenübertragungen sichtbar';
      const cookies = (x.trackingCookies||[]).map(c => '• '+c).join('<br>') || '– keine neuen Einträge';
      const csps = (x.cspBlocks||[]).map(v => \`• \${v.message}\`).join('<br>') || '– keine Verbindungen durch Sicherheitsregeln verhindert';
      const dls = (x.dlEvents||[]).map(e => '• '+e).join('<br>') || '– keine Einträge vorhanden';
      return \`
        <div class="evidence">
          <h4>Nachweis – \${label}</h4>
          <strong>Nachweis im Browser (Network):</strong>
          <pre>\${hitList}</pre>
          <strong>Neue Einträge im Browser-Speicher:</strong>
          <pre>\${cookies}</pre>
          <strong>Sicherheitsregeln haben Verbindungen verhindert:</strong>
          <pre>\${csps}</pre>
          <strong>Interne Ereignisliste (für IT):</strong>
          <pre>\${dls}</pre>
        </div>\`;
    };
    const howto = (ev.howToVerify||[]).map(s=>'• '+s.replace(/Beispiel-Requests/i,'Nachweis im Browser').replace(/HITs?/ig,'Datenübertragungen')).join('<br>');
    return \`
      \${block('Ohne Einwilligung','withoutConsent')}
      \${block('Mit Einwilligung','withConsent')}
      \${block('Bei Ablehnen','withReject')}
      <div class="evidence">
        <h4>Wo finde ich das im Browser?</h4>
        <pre>\${howto || '• Browser-Werkzeuge öffnen → „Network/Netzwerk“\\n• Nach dem Dienstnamen suchen (z. B. „google-analytics“)\\n• Seite neu laden und prüfen, ob Datenübertragungen erscheinen'}</pre>
      </div>
    \`;
  }

  function renderErrors(arr){
    if(!arr||!arr.length) return '';
    return arr.map(e=>{
      const problem   = (e.translation || 'Auf der Website ist ein Fehler aufgetreten.').replace(/HITs?/ig,'Datenübertragungen');
      const tech      = e.message || '';
      const loesung   = e.techFix || 'Die IT soll die Fehlermeldung in der Browser-Konsole prüfen und beheben.';
      const fundort   = \`Sie finden den Fehler in der Browser-Werkzeugleiste:
1) Rechtsklick → „Untersuchen“
2) Tab „Konsole“ anklicken
3) Die Meldung ist rot (Fehler) oder gelb (Warnung)\`;

      const auswirkung = /CSP|security|blocked|googletagmanager|googleadservices|facebook|tiktok|hotjar/i.test(tech)
        ? 'Marketing- oder Mess-Dienst funktioniert nicht; Auswertungen sind lückenhaft.'
        : 'Funktionen der Seite können ausfallen; Mess- oder Marketingdaten können fehlen.';

      return \`
        <div class="evidence">
          <h4>Fehler in der Website (Konsole)</h4>
          <p><strong>Problem (verständlich):</strong> \${problem}</p>
          <p><strong>Wo finde ich das im Browser?</strong><br><pre>\${fundort}</pre></p>
          <p><strong>Technischer Fehler (für IT):</strong></p>
          <pre>\${tech}</pre>
          <p><strong>Auswirkung fürs Business:</strong> \${auswirkung}</p>
          <h4>Empfohlene Lösung</h4>
          <div class="fix-suggestion">
            <code>\${loesung}</code>
            <button class="copy-button" onclick="navigator.clipboard.writeText(this.previousSibling.textContent)">Copy</button>
          </div>
        </div>\`;
    }).join('');
  }

  function renderIssues(arr){
    if(!arr||!arr.length) return '';
    return arr.map(i=>{
      const problem = (i.translation || 'Eine Verbindung zu einem externen Dienst hat nicht funktioniert.').replace(/HITs?/ig,'Datenübertragungen');
      const fundort = \`Sie finden die Blockade in den Browser-Werkzeugen:
1) „Untersuchen“ → Tab „Network/Netzwerk“
2) Seite neu laden
3) Oben im Filter den Dienstnamen eingeben (z. B. „google-analytics“, „facebook“, „kameleoon“)
4) Fehlgeschlagene Einträge sind rot/abgebrochen.\`;
      const tech = \`URL: \${i.url || '-'}\\nStatus: \${i.status ?? '-'}\`;
      const loesung = i.techFix || 'IT prüfen: Ist die Domain erlaubt (Sicherheits­richtlinie/CSP), erreichbar (DNS/Firewall) und korrekt eingebunden?';

      const auswirkung = /google-analytics|g\/collect|collect\?v=2/i.test(i.url||'')
        ? 'Besucherdaten werden nicht übertragen → Auswertungen fehlen.'
        : /googleadservices|facebook\\.com|tiktok|hotjar|kameleoon/i.test(i.url||'')
        ? 'Kampagnen-Tracking / Tests / Heatmaps funktionieren nicht.'
        : 'Externer Dienst funktioniert nicht vollständig.';

      return \`
        <div class="evidence">
          <h4>Verbindung zu externem Dienst fehlgeschlagen (Network)</h4>
          <p><strong>Problem (verständlich):</strong> \${problem}</p>
          <p><strong>Wo finde ich das im Browser?</strong><br><pre>\${fundort}</pre></p>
          <p><strong>Technischer Fehler (für IT):</strong></p>
          <pre>\${tech}</pre>
          <p><strong>Auswirkung fürs Business:</strong> \${auswirkung}</p>
          <h4>Empfohlene Lösung</h4>
          <div class="fix-suggestion">
            <code>\${loesung}</code>
            <button class="copy-button" onclick="navigator.clipboard.writeText(this.previousSibling.textContent)">Copy</button>
          </div>
        </div>\`;
    }).join('');
  }

  function renderCSP(arr){
    if(!arr||!arr.length) return '';
    return arr.map(v=>{
      const problem = 'Die Sicherheits­einstellungen der Website lassen diese Verbindung nicht zu.';
      const fundort = \`Sie finden den Blocker in der Browser-Werkzeugleiste:
1) „Untersuchen“ → Tab „Konsole“
2) Meldung in Rot: „Verbindung blockiert … (Content-Security-Policy)“
3) Die blockierte Internetadresse steht in der Meldung.\`;
      const tech = v.message || '';
      const loesung = v.techFix || 'Die IT muss die Content-Security-Policy so anpassen, dass die benötigte Domain in der passenden Directive erlaubt ist (z. B. connect-src/script-src).';

      const blocked = (tech.match(/https?:\\/\\/[^ ]+/) || [])[0] || '';
      let auswirkung = 'Betroffener Dienst kann keine Daten senden bzw. laden.';
      if (/kameleoon/i.test(blocked)) auswirkung = 'A/B-Tests und Personalisierungen werden nicht ausgewertet.';
      else if (/google-analytics|g\\/collect|collect\\?v=2/i.test(blocked)) auswirkung = 'Besucherdaten werden nicht an GA4 übertragen.';
      else if (/googleadservices|facebook\\.com|tiktok/i.test(blocked)) auswirkung = 'Kampagnen-Tracking / Remarketing funktioniert nicht.';

      return \`
        <div class="evidence">
          <h4>Verbindung durch Sicherheitsregeln blockiert (CSP)</h4>
          <p><strong>Problem (verständlich):</strong> \${problem}</p>
          <p><strong>Wo finde ich das im Browser?</strong><br><pre>\${fundort}</pre></p>
          <p><strong>Technischer Fehler (für IT):</strong></p>
          <pre>\${tech}</pre>
          <p><strong>Auswirkung fürs Business:</strong> \${auswirkung}</p>
          <h4>Empfohlene Lösung</h4>
          <div class="fix-suggestion">
            <code>\${loesung}</code>
            <button class="copy-button" onclick="navigator.clipboard.writeText(this.previousSibling.textContent)">Copy</button>
          </div>
        </div>\`;
    }).join('');
  }
})();
</script>
</body></html>`);
});

/* ----------------------------- Start & Shutdown ---------------------------- */
const server = app.listen(PORT, () => {
  console.log(`🚀 Website Scanner running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔍 Scanner UI:   http://localhost:${PORT}/`);
});
const graceful = (sig) => async () => {
  console.log(`\nReceived ${sig}, shutting down gracefully...`);
  server.close(() => { console.log('HTTP server closed.'); process.exit(0); });
  setTimeout(() => { console.warn('Force exit after 5s'); process.exit(1); }, 5000).unref();
};
process.on('SIGINT', graceful('SIGINT'));
process.on('SIGTERM', graceful('SIGTERM'));
