import express from 'express';
import { chromium } from 'playwright';
import rateLimit from 'express-rate-limit';
import cors from 'cors';

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const VERSION = process.env.GIT_SHA || '2.3.0';

// Enhanced Rate Limiting
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

/* -------------------- HIT-based consent evaluation helpers -------------------- */
// Only real tracking HITS count as consent violations.
// GTM is treated specially (no clear "hit" endpoint).
const TAG_META = {
  hasGA4:        { hitKey: 'hasGA4_HIT',        domains: ['google-analytics.com', 'g.doubleclick.net', 'region'] },
  hasUA:         { hitKey: 'hasUA_HIT',         domains: ['google-analytics.com'] },
  hasGoogleAds:  { hitKey: 'hasAds_HIT',        domains: ['googleadservices.com', 'googlesyndication.com'] },
  hasMetaPixel:  { hitKey: 'hasMeta_HIT',       domains: ['facebook.com', 'connect.facebook.net'] },
  hasTikTokPixel:{ hitKey: 'hasTikTok_HIT',     domains: ['analytics.tiktok.com'] },
  hasHotjar:     { hitKey: 'hasHotjar_HIT',     domains: ['static.hotjar.com', 'script.hotjar.com', 'hotjar.com'] },
  hasCrazyEgg:   { hitKey: 'hasCrazyEgg_HIT',   domains: ['script.crazyegg.com'] },
};

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
      if (/(^|\.)(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)/.test(hostname)) {
        throw new Error('Private/internal IPs not allowed');
      }
      if (/^\[?::1\]?$/.test(hostname)) throw new Error('Loopback IPv6 not allowed');
      if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        const p = hostname.split('.').map(Number);
        if (p[0] === 127 || p[0] === 10 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)) {
          throw new Error('Private IP ranges not allowed');
        }
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
        console.log(`Retry ${attempt + 1}/${maxRetries} for ${url}`);
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
    }
  }

  async scan(url) {
    this.reset();
    this.validateUrl(url);

    console.log(`🔍 Starting comprehensive scan of ${url}`);

    const browser = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor'
      ]
    });

    try {
      console.log('🚫 Run A: Scanning without consent (default denied)...');
      this.results.withoutConsent = await this.runSingleScan(browser, url, 'no-consent');

      console.log('✅ Run B: Scanning with consent accepted...');
      this.results.withConsent = await this.runSingleScan(browser, url, 'accept');

      console.log('❌ Run C: Scanning with consent rejected...');
      this.results.withReject = await this.runSingleScan(browser, url, 'reject');

      this.analyzeConsentCompliance();

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

    // Simulate typical CMP cookies (best effort)
    if (consentMode === 'reject') {
      await this.setConsentCookies(context, url, false);
    } else if (consentMode === 'accept') {
      await this.setConsentCookies(context, url, true);
    }

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
      window.__requestLog = [];
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

      // Fetch proxy to capture more modern requests
      const _fetch = window.fetch;
      window.fetch = async (...args) => {
        try {
          const res = await _fetch(...args);
          try {
            const url = (args && args[0] && args[0].url) || String(args[0]);
            window.__fetchLog.push({ url, status: res.status || 0, method: (args[1]?.method || 'GET') });
          } catch {}
          return res;
        } catch (err) {
          try {
            const url = (args && args[0] && args[0].url) || String(args[0]);
            window.__fetchLog.push({ url, status: 0, method: (args[1]?.method || 'GET'), error: String(err) });
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
      try {
        const response = await request.response();
        const status = response ? response.status() : 0;
        const rt = typeof request.resourceType === 'function'
          ? request.resourceType()
          : (request.resourceType || 'unknown');

        scanData.requestLog.push({
          url: request.url(),
          method: request.method(),
          resourceType: rt,
          status
        });
      } catch (e) {
        const rt = typeof request.resourceType === 'function'
          ? request.resourceType()
          : (request.resourceType || 'unknown');

        scanData.requestLog.push({
          url: request.url(),
          method: request.method(),
          resourceType: rt,
          status: 0,
          note: 'requestfinished handler error: ' + String(e)
        });
      }
    });

    page.on('requestfailed', request => {
      const failure = request.failure();
      const rt = typeof request.resourceType === 'function'
        ? request.resourceType()
        : (request.resourceType || 'unknown');

      scanData.networkIssues.push({
        url: request.url(),
        method: request.method(),
        resourceType: rt,
        status: failure?.errorText || 'Request Failed',
        priority: this.classifyNetworkPriority(request.url()),
        translation: this.translateNetworkIssue(request.url(), failure?.errorText || ''),
        techFix: this.suggestFixForUrl(request.url(), failure?.errorText),
        consentMode
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
            consentMode
          });
        }
      } catch {}
    });

    try {
      // Cookies before
      scanData.cookiesBefore = await context.cookies(url);

      // Inject Consent Mode default denied before any tag load in "no-consent"
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

      await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: 25000
      });

      // Try to interact with CMP
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

      // Merge fetch-proxy logs
      const fetchLog = await page.evaluate(() => window.__fetchLog.slice());
      for (const f of fetchLog) {
        scanData.requestLog.push({
          url: f.url,
          method: f.method || 'GET',
          resourceType: 'fetch',
          status: f.status || 0
        });
      }

      // Marketing tags detection (with HIT vs LIB separation)
      scanData.marketingTags = await this.checkMarketingTagsDeep(page, scanData.requestLog);

      // CSP violations
      const cspViolations = await page.evaluate(() => window.__cspViolations.slice());
      scanData.cspViolations = cspViolations.map(v => ({
        type: 'CSP Violation',
        message: `${v.violatedDirective} blocked ${v.blockedURI} @line:${v.lineNumber}`,
        priority: 'high',
        translation: '🔒 Sicherheitsrichtlinie blockiert Marketing-Script',
        techFix: this.suggestCSPFix(v),
        violation: v,
        consentMode
      }));

      // Cookies after
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
      {
        name: 'CookieConsent',
        value: JSON.stringify({
          stamp: Date.now(),
          necessary: true,
          preferences: acceptAll,
          statistics: acceptAll,
          marketing: acceptAll,
          method: 'explicit'
        }),
        domain, path: '/'
      },
      { name: 'cookielawinfo-checkbox-necessary', value: 'yes', domain, path: '/' },
      { name: 'cookielawinfo-checkbox-analytics', value: acceptAll ? 'yes' : 'no', domain, path: '/' },
      { name: 'cookielawinfo-checkbox-advertisement', value: acceptAll ? 'yes' : 'no', domain, path: '/' }
    ];

    for (const cookie of consentCookies) {
      try { await context.addCookies([cookie]); } catch {}
    }
  }

  async handleConsent(page, action) {
    try {
      await page.waitForTimeout(1800);

      const selectors = [
        'button', '[role="button"]', 'input[type="button"]', 'a[href]',
        '[onclick]', 'div[role="button"]', 'span[role="button"]'
      ];
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

        if (action === 'accept' && ACCEPT_RE.test(hay)) {
          await el.click({ delay: 10 });
          await page.waitForTimeout(1500);
          return true;
        }
        if (action === 'reject' && REJECT_RE.test(hay)) {
          await el.click({ delay: 10 });
          await page.waitForTimeout(1500);
          return true;
        }
      }
      return false;
    } catch (error) {
      console.log(`Consent handling failed: ${error.message}`);
      return false;
    }
  }

  async checkMarketingTagsDeep(page, requestLog) {
    // Network-based: separate HITs vs LIBs
    const hasGA4_HIT = requestLog.some(r => /(www|region\d+)\.google-analytics\.com\/g\/collect/.test(r.url));
    const hasGA4_LIB = requestLog.some(r => /gtag\/js\?id=G-/.test(r.url));
    const hasUA_HIT  = requestLog.some(r => /google-analytics\.com\/collect(\?|$)/.test(r.url));
    const hasUA_LIB  = requestLog.some(r => /google-analytics\.com\/analytics\.js/.test(r.url));
    const hasGTM_NET = requestLog.some(r => /googletagmanager\.com\/gtm\.js/.test(r.url));

    const hasAds_HIT = requestLog.some(r => /(googleadservices|googlesyndication)\.com/.test(r.url));

    const hasMeta_HIT = requestLog.some(r => /facebook\.com\/tr/.test(r.url));
    const hasMeta_LIB = requestLog.some(r => /connect\.facebook\.net/.test(r.url));

    const hasTikTok_HIT = requestLog.some(r => /analytics\.tiktok\.com/.test(r.url));
    const hasHotjar_HIT = requestLog.some(r => /(static|script)\.hotjar\.com/.test(r.url));
    const hasCrazyEgg_HIT = requestLog.some(r => /script\.crazyegg\.com/.test(r.url));

    const domBasedDetection = await page.evaluate(() => {
      const scripts = [...document.scripts];
      const iframes = [...document.querySelectorAll('iframe')];

      const hasGA4 = scripts.some(s => /gtag\/js\?id=G-/.test(s.src)) || typeof window.gtag === 'function';
      const hasUA  = scripts.some(s => /google-analytics\.com\/analytics\.js/.test(s.src)) || typeof window.ga === 'function';
      const hasGTM = scripts.some(s => /googletagmanager\.com\/gtm\.js/.test(s.src)) || Array.isArray(window.dataLayer);
      const hasGoogleAds = scripts.some(s => /google(adservices|syndication)\.com/.test(s.src)) ||
        iframes.some(f => /google(adservices|syndication)\.com/.test(f.src));
      const hasMetaPixel = typeof window.fbq === 'function' ||
        scripts.some(s => /connect\.facebook\.net/.test(s.src)) ||
        iframes.some(f => /facebook\.com/.test(f.src));
      const hasTikTokPixel = typeof window.ttq !== 'undefined' || scripts.some(s => /analytics\.tiktok\.com/.test(s.src));
      const hasHotjar = typeof window.hj === 'function' || scripts.some(s => /(static|script)\.hotjar\.com/.test(s.src));
      const hasCrazyEgg = typeof window.CE !== 'undefined' || scripts.some(s => /script\.crazyegg\.com/.test(s.src));

      const dlEvents = Array.isArray(window.dataLayer) ? window.dataLayer.map(e => e && e.event).filter(Boolean) : [];
      return { hasGA4, hasUA, hasGTM, hasGoogleAds, hasMetaPixel, hasTikTokPixel, hasHotjar, hasCrazyEgg, dlEvents,
               scriptCount: scripts.length, iframeCount: iframes.length };
    });

    // Combined presence flags (used for UI presence, not for compliance verdict)
    const merged = {
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

    return merged;
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
    this.marketingTags = defs.map(([name, prop]) => this.analyzeTagCompliance(name, prop)).filter(t => t.relevant);
  }

  analyzeTagCompliance(tagName, tagProperty) {
    const { withoutConsent, withConsent, withReject } = this.results;

    // GTM: no clear hit endpoint → not a consent violation, only informative
    if (tagProperty === 'hasGTM') {
      const presentNo = getLibPresent(withoutConsent, tagProperty);
      const presentYes = getLibPresent(withConsent, tagProperty);
      const presentRej = getLibPresent(withReject, tagProperty);
      if (!presentNo && !presentYes && !presentRej) return { relevant: false };

      const dlNo = lastDlEvents(withoutConsent);
      const hasConsentDefaultDenied = dlNo.some(e => typeof e === 'string' && e.toLowerCase().includes('consent'));

      const compliance = hasConsentDefaultDenied ? 'perfect' : 'inconsistent';
      const impact = hasConsentDefaultDenied
        ? '✅ GTM mit Consent-Initialisierung erkannt (default denied).'
        : '🤔 GTM geladen, aber kein klarer Consent-Init-Event gefunden. Manuell prüfen, ob alle Tags Consent-Checks haben.';
      const businessImpact = 'GTM Container vorhanden – Wirkung hängt von Consent-Checks der einzelnen Tags ab.';
      return {
        relevant: true,
        name: tagName,
        property: tagProperty,
        withoutConsent: presentNo,
        withAccept: presentYes,
        withReject: presentRej,
        compliance,
        impact,
        gdprRisk: hasConsentDefaultDenied ? 'none' : 'medium',
        businessImpact
      };
    }

    // Others: HIT-based only
    const meta = TAG_META[tagProperty];
    if (!meta) return { relevant: false };

    const noHit  = getHit(withoutConsent, meta.hitKey);
    const yesHit = getHit(withConsent, meta.hitKey);
    const rejHit = getHit(withReject, meta.hitKey);

    const presentSomewhere =
      getLibPresent(withoutConsent, tagProperty) ||
      getLibPresent(withConsent,   tagProperty) ||
      getLibPresent(withReject,    tagProperty);

    if (!presentSomewhere && !noHit && !yesHit && !rejHit) return { relevant: false };

    const cspBlockedNo  = cspBlockedForDomains(withoutConsent, meta.domains);
    const cspBlockedRej = cspBlockedForDomains(withReject, meta.domains);

    let compliance = 'unknown';
    let impact = '';
    let gdprRisk = 'low';

    // Ideal: Hits only after Accept
    if (!noHit && yesHit && !rejHit) {
      compliance = 'perfect';
      impact = `✅ ${tagName} respektiert Consent (HITs nur nach „Accept“).`;
      gdprRisk = 'none';
    }
    // Verstoß: Hits nach Reject
    else if (rejHit) {
      compliance = noHit ? 'inconsistent' : 'bad';
      impact = noHit
        ? `🤔 ${tagName} feuert nach „Reject“, aber nicht vor Consent. Konfigurationsfehler vermutet.`
        : `🚨 ${tagName} feuert trotz „Reject“ (HITs erkannt).`;
      gdprRisk = noHit ? 'medium' : 'high';
    }
    // Vor-Consent-Hits (aber stoppt bei Reject)
    else if (noHit && !rejHit) {
      compliance = yesHit ? 'good' : 'inconsistent';
      impact = yesHit
        ? `🟡 ${tagName} feuert vor Consent, stoppt aber bei „Reject“.`
        : `🤔 ${tagName} feuert vor Consent, aber nicht nach „Accept“. Setup prüfen.`;
      gdprRisk = 'low';
    }
    // Keine Hits überhaupt
    else if (!noHit && !yesHit && !rejHit) {
      if (cspBlockedNo || cspBlockedRej) {
        compliance = 'inconsistent';
        impact = `🟡 ${tagName} scheint durch CSP blockiert zu sein (keine Hits). Kein Consent-Verstoß, aber Tracking wirkungslos.`;
        gdprRisk = 'none';
      } else {
        compliance = 'missing';
        impact = `❌ ${tagName} ist installiert, aber es wurden keine HITs erkannt. Setup prüfen.`;
        gdprRisk = 'none';
      }
    }
    // Rest: uneinheitlich
    else {
      compliance = 'inconsistent';
      impact = `🤔 ${tagName} zeigt ein uneinheitliches Hit-Muster. Manuelle Prüfung nötig.`;
      gdprRisk = 'medium';
    }

    return {
      relevant: true,
      name: tagName,
      property: tagProperty,
      withoutConsent: noHit,   // matrix shows HITs, not just presence
      withAccept: yesHit,
      withReject: rejHit,
      compliance,
      impact,
      gdprRisk,
      businessImpact: this.getBusinessImpact(tagName, compliance),
      notes: { present: presentSomewhere, cspBlockedNo, cspBlockedRej }
    };
  }

  getBusinessImpact(tagName, compliance) {
    const impacts = {
      'Google Analytics 4': {
        perfect: 'Besucherdaten werden DSGVO-konform erfasst',
        good: 'Tracking läuft, aber rechtliches Risiko',
        bad: 'Abmahnrisiko durch Consent-Ignorierung',
        missing: 'Keine Besucherdaten → Marketing fliegt blind',
        inconsistent: 'Tracking-Verhalten inkonsistent – Datenqualität fraglich'
      },
      'Google Ads Tracking': {
        perfect: 'Conversion-Tracking DSGVO-konform',
        good: 'ROI messbar, aber rechtliches Risiko',
        bad: 'Abmahnrisiko + ungenaue Kampagnen-Daten',
        missing: 'Werbebudget-Verschwendung durch fehlende Messung',
        inconsistent: 'Conversions werden inkonsistent erfasst – Optimierung leidet'
      },
      'Meta Pixel (Facebook/Instagram)': {
        perfect: 'Social Media ROI DSGVO-konform messbar',
        good: 'Retargeting funktioniert, rechtliches Risiko',
        bad: 'Abmahnrisiko bei Facebook/Instagram Ads',
        missing: 'Facebook/Instagram Ads laufen blind',
        inconsistent: 'Events feuern inkonsistent – Zielgruppenaufbau gestört'
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
    const translations = {
      'net::ERR_BLOCKED_BY_CLIENT': '🚫 AdBlocker verhindert Marketing-Tracking - Umsatzverlust möglich',
      'Content Security Policy': '🔒 Sicherheitseinstellungen blockieren kritische Marketing-Scripts',
      'googleadservices': '🎯 Google Ads Conversion-Tracking blockiert - ROI nicht messbar, Budget-Optimierung unmöglich',
      'connect.facebook.net': '📱 Meta Pixel blockiert - Facebook/Instagram Ads Performance unbekannt',
      'googletagmanager': '📊 Google Tag Manager blockiert - alle Marketing-Tags betroffen',
      'analytics.tiktok.com': '🎵 TikTok Pixel blockiert - TikTok Ads ROI unbekannt',
      'static.hotjar.com': '🖱️ Hotjar Heatmap-Tracking blockiert - Nutzerverhalten unbekannt',
      'script.hotjar.com': '🖱️ Hotjar Heatmap-Tracking blockiert - Nutzerverhalten unbekannt',
      'CORS': '🌐 Cross-Origin Problem - externes Marketing-Script nicht ladbar',
      'ERR_NAME_NOT_RESOLVED': '🌐 DNS-Problem - Marketing-Service nicht erreichbar',
      'ERR_INTERNET_DISCONNECTED': '📡 Internetverbindung unterbrochen'
    };
    for (let [key, translation] of Object.entries(translations)) {
      if (errorMessage.includes(key)) return translation;
    }
    return '⚠️ Technischer Fehler gefunden - kann Marketing-Performance beeinträchtigen';
  }

  translateNetworkIssue(url, status) {
    if (url.includes('googleadservices') || url.includes('googlesyndication')) {
      return `🎯 Google Ads (${status}) - Conversion-Tracking gestört, Budget-Verschwendung wahrscheinlich`;
    }
    if (url.includes('facebook.net') || url.includes('facebook.com') || url.includes('meta')) {
      return `📱 Meta Pixel (${status}) - Social Media ROI unbekannt, Retargeting unmöglich`;
    }
    if (url.includes('analytics') && url.includes('google')) {
      return `📊 Google Analytics (${status}) - Besucherdaten verloren, Optimierung unmöglich`;
    }
    if (url.includes('tiktok')) {
      return `🎵 TikTok Pixel (${status}) - TikTok Kampagnen laufen unoptimiert`;
    }
    if (url.includes('hotjar')) {
      return `🖱️ Hotjar (${status}) - Nutzerverhalten-Analyse nicht möglich`;
    }
    return `⚠️ Marketing-Tool blockiert (${status}) - Performance-Impact unbekannt`;
  }

  suggestFix(errorMessage) {
    if (errorMessage.includes('googleadservices')) {
      return `CSP erweitern:\nContent-Security-Policy:\n  script-src ... https://www.googleadservices.com;\n  connect-src ... https://www.googleadservices.com;`;
    }
    if (errorMessage.includes('connect.facebook.net')) {
      return `CSP erweitern:\nContent-Security-Policy:\n  script-src ... https://connect.facebook.net;\n  connect-src ... https://connect.facebook.net;`;
    }
    if (errorMessage.includes('googletagmanager')) {
      return `CSP erweitern:\nContent-Security-Policy:\n  script-src ... https://www.googletagmanager.com;\n  connect-src ... https://www.googletagmanager.com;`;
    }
    if (errorMessage.includes('static.hotjar.com') || errorMessage.includes('script.hotjar.com')) {
      return `CSP erweitern:\nContent-Security-Policy:\n  script-src ... https://static.hotjar.com https://script.hotjar.com;\n  connect-src ... https://*.hotjar.com wss://*.hotjar.com;`;
    }
    if (errorMessage.includes('Content Security Policy')) {
      return 'CSP-Header überprüfen und alle Marketing-Domains in script-src und connect-src whitelisten';
    }
    return 'Entwickler-Konsole öffnen, Fehlerstack analysieren, betroffene Datei reparieren';
  }

  suggestFixForUrl(url, error) {
    try {
      const domain = new URL(url).hostname;
      if (error?.includes('CSP') || /BLOCKED/i.test(error || '')) {
        return `CSP-Header erweitern:\nContent-Security-Policy:\n  script-src ... https://${domain};\n  connect-src ... https://${domain};`;
      }
      if (error?.includes('CORS')) {
        return `CORS-Header vom Server ${domain} konfigurieren:\nAccess-Control-Allow-Origin: ${new URL(url).origin}`;
      }
      if (error?.includes('DNS') || error?.includes('NAME_NOT_RESOLVED')) {
        return `DNS-Konfiguration prüfen: nslookup ${domain}`;
      }
      return `Server-Erreichbarkeit von ${domain} prüfen: curl -I https://${domain}`;
    } catch {
      return 'URL-Format prüfen und Server-Konnektivität testen';
    }
  }

  suggestCSPFix(violation) {
    try {
      const domain = new URL(violation.blockedURI).hostname;
      const directive = violation.violatedDirective;
      return `CSP-Directive erweitern:\nContent-Security-Policy:\n  ${directive} ... https://${domain};`;
    } catch {
      return `CSP-Policy überprüfen: ${violation.violatedDirective} für ${violation.blockedURI}`;
    }
  }

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
    const highPriorityIssues = [...allErrors, ...allNetworkIssues, ...allCSPViolations]
      .filter(issue => issue.priority === 'high' || issue.priority === 'critical').length;

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
      rawResults: this.results
    };
  }
}

const scanner = new UltimateWebsiteScanner();

// API endpoint
app.post('/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'Missing URL' });
  }
  try {
    console.log(`Starting scan for: ${url}`);
    const results = await scanner.scanWithRetry(url);
    res.json(results);
  } catch (error) {
    console.error('Scan failed:', error);
    res.status(500).json({
      error: 'Scan failed',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: VERSION,
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Version endpoint
app.get('/version', (req, res) => {
  res.json({
    version: VERSION,
    buildTime: new Date().toISOString(),
    nodeVersion: process.version
  });
});

// Frontend Route - Das komplette UI mit UX-Verbesserungen
// Frontend Route - Fixed template literal escaping
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultimate Website Scanner - DSGVO & Marketing Check</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6; color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; padding: 20px;
        }
        .container {
            max-width: 1200px; margin: 0 auto; background: white;
            border-radius: 16px; box-shadow: 0 25px 50px rgba(0,0,0,0.15);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            color: white; padding: 50px 30px; text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 20px; font-weight: 700; line-height: 1.2; }
        .header p { opacity: 0.9; font-size: 1.1em; margin-bottom: 15px; max-width: 800px; margin-left: auto; margin-right: auto; }
        .features {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px; padding: 30px; background: rgba(255,255,255,0.1);
            margin-top: 30px; border-radius: 12px;
        }
        .feature { text-align: center; padding: 20px; }
        .feature-icon { font-size: 2.5em; margin-bottom: 15px; }
        .feature h3 { margin-bottom: 10px; font-size: 1.2em; }
        .feature p { font-size: 0.95em; opacity: 0.9; }
        .form-section { padding: 50px; }
        .input-group { margin-bottom: 30px; }
        label {
            display: block; margin-bottom: 12px; font-weight: 600;
            color: #2d3748; font-size: 1.1em;
        }
        .url-input-container { position: relative; }
        input[type="url"] {
            width: 100%; padding: 20px; border: 2px solid #e2e8f0;
            border-radius: 12px; font-size: 16px; transition: all 0.3s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        input[type="url"]:focus {
            border-color: #667eea; outline: none;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        input[type="url"].valid { border-color: #48bb78; }
        input[type="url"].invalid { border-color: #f56565; }
        .url-validation {
            font-size: 0.85em; margin-top: 8px; padding: 5px 0;
            min-height: 20px;
        }
        .url-validation.valid { color: #48bb78; }
        .url-validation.invalid { color: #f56565; }
        .scan-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 22px 50px; border-radius: 12px;
            font-size: 18px; font-weight: 600; cursor: pointer; width: 100%;
            transition: all 0.3s; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            position: relative; overflow: hidden;
        }
        .scan-button:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6);
        }
        .scan-button:disabled {
            opacity: 0.6; cursor: not-allowed; transform: none;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.2);
        }
        .quick-demo {
            text-align: center; margin: 20px 0; padding: 15px;
            background: #f7fafc; border-radius: 8px; border: 1px solid #e2e8f0;
        }
        .demo-button {
            background: #4299e1; color: white; border: none; padding: 8px 16px;
            border-radius: 6px; font-size: 0.9em; cursor: pointer; margin: 0 5px;
        }
        .loading {
            display: none; text-align: center; padding: 40px; color: #667eea;
            background: #f8f9fa; margin: 20px; border-radius: 12px;
        }
        .progress-container {
            margin: 25px 0;
        }
        .progress-bar {
            width: 100%; height: 8px; background: #e2e8f0; border-radius: 4px;
            overflow: hidden; position: relative;
        }
        .progress-fill {
            height: 100%; background: linear-gradient(90deg, #667eea, #764ba2);
            width: 0%; transition: width 0.5s ease; border-radius: 4px;
            position: relative;
        }
        .progress-fill::after {
            content: '';
            position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            animation: shimmer 1.5s infinite;
        }
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        .loading-steps {
            display: flex; justify-content: space-between; margin-top: 15px;
            font-size: 0.85em;
        }
        .loading-step {
            padding: 8px 12px; background: #e2e8f0; border-radius: 15px;
            transition: all 0.3s;
        }
        .loading-step.active {
            background: #667eea; color: white; transform: scale(1.05);
        }
        .loading-step.completed {
            background: #48bb78; color: white;
        }
        .results { display: none; padding: 0 50px 50px; }
        .risk-indicator {
            padding: 25px; border-radius: 12px; margin-bottom: 30px;
            font-weight: 600; text-align: center; position: relative;
            overflow: hidden;
        }
        .risk-indicator::before {
            content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            animation: sweep 2s infinite;
        }
        @keyframes sweep {
            0% { left: -100%; }
            100% { left: 100%; }
        }
        .risk-high {
            background: linear-gradient(135deg, #fed7d7 0%, #feb2b2 100%);
            color: #c53030; border: 2px solid #fc8181;
        }
        .risk-medium {
            background: linear-gradient(135deg, #fefcbf 0%, #faf089 100%);
            color: #d69e2e; border: 2px solid #f6e05e;
        }
        .risk-low {
            background: linear-gradient(135deg, #c6f6d5 0%, #9ae6b4 100%);
            color: #2f855a; border: 2px solid #68d391;
        }
        .section {
            margin-bottom: 30px; border: 1px solid #e2e8f0;
            border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .section:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.15);
        }
        .section-header {
            background: linear-gradient(135deg, #f8f9fa 0%, #e2e8f0 100%);
            padding: 20px; font-weight: 600; display: flex;
            justify-content: space-between; align-items: center; font-size: 1.1em;
            cursor: pointer; user-select: none;
        }
        .section-header:hover {
            background: linear-gradient(135deg, #edf2f7 0%, #d4e5f1 100%);
        }
        .badge {
            background: #4299e1; color: white; padding: 6px 12px;
            border-radius: 15px; font-size: 0.85em; font-weight: 500;
            display: inline-flex; align-items: center; gap: 5px;
        }
        .badge.high { background: #e53e3e; }
        .badge.medium { background: #d69e2e; }
        .badge.critical { background: #9f1239; }
        .section-content { padding: 25px; }
        .compliance-item {
            padding: 20px; margin: 15px 0; border-radius: 10px;
            border-left: 5px solid; position: relative;
            transition: all 0.3s;
        }
        .compliance-item:hover {
            transform: translateX(5px);
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .compliance-perfect { background: #f0fff4; border-left-color: #38a169; }
        .compliance-good { background: #fefcbf; border-left-color: #d69e2e; }
        .compliance-bad { background: #fff5f5; border-left-color: #e53e3e; }
        .compliance-missing { background: #f7fafc; border-left-color: #a0aec0; }
        .compliance-inconsistent { background: #fdf2e9; border-left-color: #ed8936; }
        .consent-matrix {
            display: grid; grid-template-columns: 1fr 1fr 1fr;
            gap: 12px; margin-top: 15px; font-size: 0.9em;
            background: #f8f9fa; padding: 15px; border-radius: 8px;
        }
        .consent-result {
            text-align: center; padding: 10px; border-radius: 6px;
            font-weight: 500; transition: transform 0.2s;
        }
        .consent-result:hover { transform: scale(1.05); }
        .consent-pass { background: #c6f6d5; color: #2f855a; }
        .consent-fail { background: #fed7d7; color: #c53030; }
        .issue-item {
            background: #fff5f5; border: 1px solid #feb2b2;
            border-radius: 10px; padding: 20px; margin: 15px 0;
            transition: all 0.3s;
        }
        .issue-item:hover {
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        .tech-details {
            background: #f7fafc; padding: 15px; border-radius: 8px;
            margin-top: 12px; font-size: 0.95em; color: #4a5568;
            font-family: 'Monaco', 'Menlo', monospace;
        }
        .fix-suggestion {
            background: #e6fffa; border: 1px solid #4fd1c7;
            padding: 15px; border-radius: 8px; margin-top: 12px;
            font-family: 'Monaco', 'Menlo', monospace; font-size: 0.9em;
            position: relative;
        }
        .copy-button {
            position: absolute; top: 8px; right: 8px;
            background: #319795; color: white; border: none;
            padding: 4px 8px; border-radius: 4px; font-size: 0.8em;
            cursor: pointer;
        }
        .priority-critical { border-left: 5px solid #c53030; }
        .priority-high { border-left: 5px solid #e53e3e; }
        .priority-medium { border-left: 5px solid #d69e2e; }
        .priority-low { border-left: 5px solid #4299e1; }
        .export-buttons {
            display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap;
        }
        .export-btn {
            background: #4a5568; color: white; border: none;
            padding: 10px 16px; border-radius: 6px; cursor: pointer;
            font-size: 0.9em; display: flex; align-items: center; gap: 5px;
        }
        .export-btn:hover { background: #2d3748; }
        .footer {
            text-align: center; padding: 30px; background: #f8f9fa;
            color: #718096; font-size: 0.9em;
        }
        .tooltip {
            position: relative; cursor: help;
            border-bottom: 1px dotted #999;
        }
        .tooltip:hover::after {
            content: attr(data-tooltip);
            position: absolute; bottom: 100%; left: 50%;
            transform: translateX(-50%); background: #2d3748; color: white;
            padding: 8px 12px; border-radius: 6px; font-size: 0.85em;
            white-space: nowrap; z-index: 1000;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }
        @media (max-width: 768px) {
            .container { margin: 10px; }
            .header { padding: 30px 20px; }
            .header h1 { font-size: 1.8em; }
            .form-section, .results { padding: 30px 20px; }
            .features { grid-template-columns: 1fr; gap: 15px; padding: 20px; }
            .consent-matrix { grid-template-columns: 1fr; gap: 8px; }
            .loading-steps { flex-direction: column; gap: 8px; }
            .export-buttons { justify-content: center; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Website-Scanner: DSGVO & Marketing Check</h1>
            <p>Finde sofort heraus, ob deine Website rechtssicher funktioniert und wo du Umsatz verlierst</p>
            <p style="font-size: 0.95em; opacity: 0.8;">Unser 3-Session-Test prüft Cookie-Banner, Marketing-Tags und CSP-Einstellungen</p>

            <div class="features">
                <div class="feature">
                    <div class="feature-icon">🍪</div>
                    <h3>Cookie-Banner-Test</h3>
                    <p>3-Wege-Analyse: ohne Consent, mit Accept, mit Reject</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🔒</div>
                    <h3>CSP-Violations</h3>
                    <p>Findet blockierte Marketing-Scripts durch Sicherheitsrichtlinien</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">📊</div>
                    <h3>DSGVO-Compliance</h3>
                    <p>Überprüft Google Analytics, Meta Pixel, TikTok & mehr</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">💰</div>
                    <h3>Business Impact</h3>
                    <p>Zeigt konkrete Umsatz-Verluste und Lösungsansätze</p>
                </div>
            </div>
        </div>

        <div class="form-section">
            <form id="scanForm">
                <div class="input-group">
                    <label for="url">Website-URL für vollständige Analyse:</label>
                    <div class="url-input-container">
                        <input
                            type="url"
                            id="url"
                            placeholder="https://ihre-website.de"
                            required
                        >
                        <div class="url-validation" id="urlValidation"></div>
                    </div>
                </div>
                <button type="submit" class="scan-button" id="scanBtn">
                    🔍 Vollständigen 3-Session-Scan starten
                </button>
            </form>

            <div class="loading" id="loading">
                <h3>⏳ Führe umfassende DSGVO & Marketing-Analyse durch...</h3>
                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                    <div class="loading-steps">
                        <div class="loading-step" id="step1">1. Ohne Consent</div>
                        <div class="loading-step" id="step2">2. Mit Accept</div>
                        <div class="loading-step" id="step3">3. Mit Reject</div>
                        <div class="loading-step" id="step4">4. Analyse</div>
                    </div>
                </div>
                <p id="loadingText">Initialisiere Browser...</p>
                <p><small>Das kann 60-90 Sekunden dauern</small></p>
            </div>
        </div>

        <div class="results" id="results"></div>

        <div class="footer">
            <p>Powered by ReguKit Compliance Software</p>
            <p><small>Sichere Analyse ohne Datenspeicherung • Made in Germany</small></p>
        </div>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const scanForm = document.getElementById('scanForm');
            const urlInput = document.getElementById('url');
            const scanBtn = document.getElementById('scanBtn');
            const loadingDiv = document.getElementById('loading');
            const resultsDiv = document.getElementById('results');
            const progressFill = document.getElementById('progressFill');
            const loadingText = document.getElementById('loadingText');
            const urlValidation = document.getElementById('urlValidation');

            const scanSteps = [
                'Initialisiere Browser...',
                'Scanne ohne Consent...',
                'Scanne mit Consent accepted...',
                'Scanne mit Consent rejected...',
                'Analysiere Ergebnisse...',
                'Generiere Report...'
            ];

            let currentStep = 0;
            let progressInterval;

            function updateProgress() {
                if (currentStep < scanSteps.length) {
                    loadingText.textContent = scanSteps[currentStep];
                    const progress = (currentStep / scanSteps.length) * 100;
                    progressFill.style.width = \`\${progress}%\`;
                    currentStep++;
                } else {
                    clearInterval(progressInterval);
                    progressFill.style.width = '100%';
                }
            }

            urlInput.addEventListener('input', (e) => {
                const url = e.target.value.trim();
                const isValid = validateUrl(url);
                if (url === '') {
                    urlValidation.textContent = '';
                    urlInput.classList.remove('valid', 'invalid');
                } else if (isValid) {
                    urlValidation.textContent = 'Gültige URL ✔️';
                    urlValidation.classList.remove('invalid');
                    urlValidation.classList.add('valid');
                    urlInput.classList.remove('invalid');
                    urlInput.classList.add('valid');
                    scanBtn.disabled = false;
                } else {
                    urlValidation.textContent = 'Ungültige URL. Muss mit http:// oder https:// beginnen.';
                    urlValidation.classList.remove('valid');
                    urlValidation.classList.add('invalid');
                    urlInput.classList.remove('valid');
                    urlInput.classList.add('invalid');
                    scanBtn.disabled = true;
                }
            });

            function validateUrl(url) {
                try {
                    const u = new URL(url);
                    return u.protocol === 'http:' || u.protocol === 'https:';
                } catch (e) {
                    return false;
                }
            }

            scanForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const url = urlInput.value.trim();
                if (!validateUrl(url)) {
                    alert('Bitte eine gültige URL eingeben (inkl. http:// oder https://)');
                    return;
                }

                scanBtn.disabled = true;
                loadingDiv.style.display = 'block';
                resultsDiv.style.display = 'none';
                resultsDiv.innerHTML = '';

                currentStep = 0;
                updateProgress();
                progressInterval = setInterval(updateProgress, 15000); // Update every 15s

                try {
                    const response = await fetch('/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url })
                    });

                    clearInterval(progressInterval);
                    progressFill.style.width = '100%';
                    loadingText.textContent = 'Report fertiggestellt! 🎉';

                    const results = await response.json();

                    if (!response.ok) {
                        throw new Error(results.details || 'Unknown error');
                    }

                    setTimeout(() => {
                        renderResults(results);
                        loadingDiv.style.display = 'none';
                        resultsDiv.style.display = 'block';
                        scanBtn.disabled = false;
                    }, 1000);

                } catch (error) {
                    clearInterval(progressInterval);
                    loadingDiv.style.display = 'none';
                    scanBtn.disabled = false;
                    alert('Scan failed: ' + error.message);
                    console.error('Scan Error:', error);
                }
            });

            function renderResults(data) {
                let html = '';

                const riskLevel = data.summary.highPriorityIssues > 0 ? 'high' : data.summary.totalIssues > 0 ? 'medium' : 'low';
                const riskText = data.summary.highPriorityIssues > 0 ? 'Hohes Risiko 🚨' : data.summary.totalIssues > 0 ? 'Mittleres Risiko 🟡' : 'Niedriges Risiko ✅';

                html += \`<div class="risk-indicator risk-\${riskLevel}"><h1>\${riskText}</h1><p>Gefundene Probleme: \${data.summary.totalIssues} (davon \${data.summary.highPriorityIssues} kritisch)</p></div>\`;

                html += \`<div class="export-buttons"><button class="export-btn" onclick="downloadJSON(\${JSON.stringify(data).replace(/"/g, '&quot;')})">Export JSON</button></div>\`;

                html += \`<h2>Marketing & DSGVO Compliance Check</h2>\`;
                data.summary.marketingTags.forEach(tag => {
                    html += \`
                        <div class="compliance-item compliance-\${tag.compliance}">
                            <h3>\${tag.name} (\${tag.compliance === 'perfect' ? '✅ Perfekt' : tag.compliance === 'bad' ? '❌ Verstoß' : tag.compliance === 'good' ? '🟡 Eingeschränkt' : tag.compliance === 'missing' ? '❌ Fehlend' : '🤔 Unklar'})</h3>
                            <p>\${tag.impact}</p>
                            <div class="consent-matrix">
                                <div class="consent-result \${tag.withoutConsent ? 'consent-fail' : 'consent-pass'}">Ohne Consent: \${tag.withoutConsent ? 'HIT' : 'KEIN HIT'}</div>
                                <div class="consent-result \${tag.withAccept ? 'consent-pass' : 'consent-fail'}">Mit Accept: \${tag.withAccept ? 'HIT' : 'KEIN HIT'}</div>
                                <div class="consent-result \${tag.withReject ? 'consent-fail' : 'consent-pass'}">Mit Reject: \${tag.withReject ? 'HIT' : 'KEIN HIT'}</div>
                            </div>
                            <div class="tech-details"><strong>Business Impact:</strong> \${tag.businessImpact}</div>
                        </div>
                    \`;
                });

                html += \`<h2>Technische Probleme (\${data.details.errors.length + data.details.networkIssues.length + data.details.cspViolations.length})</h2>\`;
                html += renderErrors(data.details.errors);
                html += renderNetworkIssues(data.details.networkIssues);
                html += renderCSPViolations(data.details.cspViolations);

                resultsDiv.innerHTML = html;
            }

            function renderErrors(errors) {
                if (!errors || errors.length === 0) return '';
                return errors.map(error => \`
                    <div class="issue-item priority-\${error.priority}">
                        <h4>\${error.type}</h4>
                        <p><strong>Problem:</strong> \${error.translation}</p>
                        <div class="tech-details"><strong>Technische Details:</strong> \${error.message}</div>
                        <div class="fix-suggestion">
                            <strong>Lösung:</strong><br>
                            <code>\${error.techFix}</code>
                            <button class="copy-button" onclick="copyToClipboard('\${error.techFix.replace(/'/g, "\\'")}')">Copy</button>
                        </div>
                    </div>
                \`).join('');
            }

            function renderNetworkIssues(issues) {
                if (!issues || issues.length === 0) return '';
                return issues.map(issue => \`
                    <div class="issue-item priority-\${issue.priority}">
                        <h4>Netzwerk Problem</h4>
                        <p><strong>Problem:</strong> \${issue.translation}</p>
                        <div class="tech-details"><strong>URL:</strong> \${issue.url}<br><strong>Status:</strong> \${issue.status}</div>
                        <div class="fix-suggestion">
                            <strong>Lösung:</strong><br>
                            <code>\${issue.techFix}</code>
                            <button class="copy-button" onclick="copyToClipboard('\${issue.techFix.replace(/'/g, "\\'")}')">Copy</button>
                        </div>
                    </div>
                \`).join('');
            }

            function renderCSPViolations(violations) {
                if (!violations || violations.length === 0) return '';
                return violations.map(violation => \`
                    <div class="issue-item priority-\${violation.priority}">
                        <h4>\${violation.type}</h4>
                        <p><strong>Problem:</strong> \${violation.translation}</p>
                        <div class="tech-details"><strong>Details:</strong> \${violation.message}</div>
                        <div class="fix-suggestion">
                            <strong>CSP Fix:</strong><br>
                            <code>\${violation.techFix}</code>
                            <button class="copy-button" onclick="copyToClipboard('\${violation.techFix.replace(/'/g, "\\'")}')">Copy</button>
                        </div>
                    </div>
                \`).join('');
            }

            // Helper functions
            function toggleSection(element) {
                const content = element.nextElementSibling;
                if (content.style.display === "block") {
                    content.style.display = "none";
                } else {
                    content.style.display = "block";
                }
            }

            function downloadJSON(data) {
                const filename = 'scan-report-' + new Date().toISOString().slice(0, 10) + '.json';
                const jsonStr = JSON.stringify(data, null, 2);
                const blob = new Blob([jsonStr], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }

            window.toggleSection = toggleSection;
            window.downloadJSON = downloadJSON;

            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('Code in die Zwischenablage kopiert!');
                }).catch(err => {
                    console.error('Fehler beim Kopieren', err);
                });
            }
            window.copyToClipboard = copyToClipboard;
        });
    </script>
</body>
</html>
`);
});

const server = app.listen(PORT, () => {
  console.log(`🚀 Website Scanner running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔍 Scanner UI: http://localhost:${PORT}/`);
});

const graceful = (sig) => async () => {
  console.log(`\nReceived ${sig}, shutting down gracefully...`);
  server.close(() => {
    console.log('HTTP server closed.');
    process.exit(0);
  });
  setTimeout(() => {
    console.warn('Force exit after 5s');
    process.exit(1);
  }, 5000).unref();
};

process.on('SIGINT', graceful('SIGINT'));
process.on('SIGTERM', graceful('SIGTERM'));
