// server.js – Ultimate Website Scanner (Best of Both)
// Fokus: schnelle DSGVO-Checks + robuste Consent-Erkennung, ohne schwere Evidence-Features

import express from 'express';
import { chromium } from 'playwright';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import helmet from 'helmet';

const app = express();
app.set('trust proxy', 1); // Proxy-aware (Render/Heroku/…)

// ---------------- Meta ----------------
const PORT = process.env.PORT || 3000;
const VERSION = process.env.GIT_SHA || '2.2.1';

// --------------- Security --------------
app.use(helmet({
  // wir liefern eine Single-Page-UI + JSON, also unkritisch
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

// --------------- CORS/JSON --------------
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ------------- Rate Limiting ------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Rate limit exceeded. Max 20 scans per 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/scan', limiter);

// =====================================================
//                 Scanner-Klasse
// =====================================================
class UltimateWebsiteScanner {
  constructor() {
    this.reset();
  }

  reset() {
    this.errors = [];
    this.networkIssues = [];
    this.marketingTags = [];
    this.results = {
      withoutConsent: null,
      withConsent: null,
      withReject: null
    };
  }

  // URL-Validierung (HTTP/S, blocke private IPv4/Loopback)
  validateUrl(url) {
    try {
      const u = new URL(url);
      if (!/^https?:$/.test(u.protocol)) {
        throw new Error('Only HTTP/HTTPS URLs allowed');
      }
      const hostname = u.hostname.toLowerCase();

      // Private IPv4 / localhost blocken
      if (/(^|\.)(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)/.test(hostname)) {
        throw new Error('Private/internal IPs not allowed');
      }
      // IPv6 Loopback
      if (/^\[?::1\]?$/.test(hostname)) {
        throw new Error('Loopback IPv6 not allowed');
      }
      // Dot-decimal IPs prüfen und private Ranges blocken
      if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        const parts = hostname.split('.').map(Number);
        if (parts[0] === 127 || parts[0] === 10 ||
           (parts[0] === 192 && parts[1] === 168) ||
           (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)) {
          throw new Error('Private IP ranges not allowed');
        }
      }
      return true;
    } catch (error) {
      throw new Error('Invalid URL: ' + error.message);
    }
  }

  // Retry mit einfachem Exponential Backoff
  async scanWithRetry(url, maxRetries = 2) {
    let delay = 3000;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await this.scan(url);
      } catch (error) {
        if (attempt === maxRetries) throw error;
        console.log(`Retry ${attempt + 1}/${maxRetries} for ${url}`);
        await new Promise(r => setTimeout(r, delay));
        delay *= 2;
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
        // Wichtig: NICHT --disable-web-security (würde CSP/CORS verfälschen)
        '--disable-features=VizDisplayCompositor'
      ]
    });

    try {
      console.log('🚫 Run A: Scanning without consent...');
      this.results.withoutConsent = await this.runSingleScan(browser, url, 'no-consent');

      console.log('✅ Run B: Scanning with consent accepted...');
      this.results.withConsent = await this.runSingleScan(browser, url, 'accept');

      console.log('❌ Run C: Scanning with consent rejected...');
      this.results.withReject = await this.runSingleScan(browser, url, 'reject');

      // Auswertung
      this.analyzeConsentCompliance();
    } finally {
      await browser.close();
    }

    return this.getComprehensiveResults(url);
  }

  async runSingleScan(browser, url, consentMode) {
    const context = await browser.newContext({
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
      viewport: { width: 1920, height: 1080 },
      ignoreHTTPSErrors: true
    });

    // Timeouts
    context.setDefaultNavigationTimeout?.(30000);
    context.setDefaultTimeout?.(10000);

    // Consent-Cookies (best-effort)
    if (consentMode === 'reject') {
      await this.setConsentCookies(context, url, false);
    } else if (consentMode === 'accept') {
      await this.setConsentCookies(context, url, true);
    }

    const page = await context.newPage();

    // Consent Mode v2 „default“ setzen (macht GA4-Signale deterministischer)
    await page.addInitScript(({ mode }) => {
      window.dataLayer = window.dataLayer || [];
      function gtag(){ window.dataLayer.push(arguments); }
      gtag('consent', 'default', {
        ad_storage:         mode === 'accept' ? 'granted' : 'denied',
        analytics_storage:  mode === 'accept' ? 'granted' : 'denied',
        ad_user_data:       mode === 'accept' ? 'granted' : 'denied',
        ad_personalization: mode === 'accept' ? 'granted' : 'denied',
        functionality_storage: 'granted',
        security_storage:      'granted'
      });
    }, { mode: consentMode });

    const scanData = {
      errors: [],
      networkIssues: [],
      cspViolations: [],
      marketingTags: {},
      requestLog: [],
      consentMode
    };

    // CSP-Violations sammeln
    await page.addInitScript(() => {
      window.__cspViolations = [];
      window.addEventListener('securitypolicyviolation', e => {
        window.__cspViolations.push({
          blockedURI: e.blockedURI,
          violatedDirective: e.violatedDirective,
          lineNumber: e.lineNumber || 0,
          sourceFile: e.sourceFile || '',
          originalPolicy: e.originalPolicy
        });
      });
    });

    // Console Errors
    page.on('console', msg => {
      if (msg.type() === 'error') {
        scanData.errors.push({
          type: 'Console Error',
          message: msg.text(),
          location: msg.location(),
          priority: this.classifyErrorPriority(msg.text()),
          translation: this.translateError(msg.text()),
          techFix: this.suggestFix(msg.text()),
          consentMode
        });
      }
    });

    // Uncaught Exceptions
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

    // Network Monitoring
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
      scanData.networkIssues.push({
        url: request.url(),
        method: request.method(),
        status: failure?.errorText || 'Request Failed',
        priority: this.classifyNetworkPriority(request.url()),
        translation: this.translateNetworkIssue(request.url(), failure?.errorText || ''),
        techFix: this.suggestFixForUrl(request.url(), failure?.errorText),
        consentMode
      });
    });

    page.on('response', response => {
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
    });

    try {
      await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: 20000
      });

      // CMP bedienen (Shortcuts + Heuristik)
      if (consentMode === 'accept') {
        await this.handleConsent(page, 'accept');
      } else if (consentMode === 'reject') {
        await this.handleConsent(page, 'reject');
      }

      // kurze Nachladephase für Tags
      await page.evaluate(() => { window.scrollTo(0, document.body.scrollHeight); });
      await Promise.race([
        page.waitForLoadState('networkidle', { timeout: 3000 }).catch(() => {}),
        page.waitForTimeout(1500)
      ]);

      // Tag-Erkennung
      scanData.marketingTags = await this.checkMarketingTagsDeep(page, scanData.requestLog);

      // CSP-Violations einsammeln
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

  // Consent-Cookies (best-effort)
  async setConsentCookies(context, url, acceptAll) {
    try {
      const { hostname, protocol } = new URL(url);
      const domain = hostname.startsWith('.') ? hostname : '.' + hostname;
      const base = `${protocol}//${hostname}`;

      const cookies = [
        {
          name: 'CookieConsent',
          value: encodeURIComponent(JSON.stringify({
            stamp: Date.now(),
            necessary: true,
            preferences: acceptAll,
            statistics: acceptAll,
            marketing: acceptAll,
            method: 'explicit'
          })),
          domain, path: '/', url: base, httpOnly: false, secure: true, sameSite: 'Lax'
        },
        { name: 'cookielawinfo-checkbox-necessary',     value: 'yes',           domain, path: '/', url: base },
        { name: 'cookielawinfo-checkbox-analytics',     value: acceptAll ? 'yes' : 'no', domain, path: '/', url: base },
        { name: 'cookielawinfo-checkbox-advertisement', value: acceptAll ? 'yes' : 'no', domain, path: '/', url: base }
      ];

      await context.addCookies(cookies);
    } catch {
      // Ignorieren (nur Heuristik)
    }
  }

  // CMP-Shortcuts + Heuristik
  async handleConsent(page, action) {
    try {
      const click = async (sel) => {
        const el = await page.$(sel);
        if (el && await el.isVisible()) {
          await el.click();
          await page.waitForTimeout(1500);
          return true;
        }
        return false;
      };

      await page.waitForTimeout(2000);

      // 1) OneTrust
      if (action === 'accept' && await click('#onetrust-accept-btn-handler')) return true;
      if (action === 'reject' && await click('#onetrust-reject-all-handler')) return true;

      // 2) Cookiebot
      if (action === 'accept' && await click('#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll')) return true;
      if (action === 'reject' && await click('#CybotCookiebotDialogBodyButtonDecline')) return true;

      // 3) Complianz
      if (action === 'accept' && await click('.cmplz-accept')) return true;
      if (action === 'reject' && await click('.cmplz-deny')) return true;

      // 4) Klaro
      if (action === 'accept' && await click('.klaro .cm-btn-success')) return true;
      if (action === 'reject' && await click('.klaro .cm-btn-danger')) return true;

      // 5) Borlabs
      if (action === 'accept' && await click('.borlabs-cookie ._brlbs-accept-all')) return true;
      if (action === 'reject' && await click('.borlabs-cookie ._brlbs-btn-accept-only-essential')) return true;

      // Heuristik als Fallback
      const buttons = await page.$$('button, [role="button"], input[type="button"], a, div[onclick], span[onclick]');
      for (const btn of buttons) {
        const text = (await btn.textContent() || '').toLowerCase();
        const ariaLabel = (await btn.getAttribute('aria-label') || '').toLowerCase();
        const className = (await btn.getAttribute('class') || '').toLowerCase();
        const id = (await btn.getAttribute('id') || '').toLowerCase();

        const allText = `${text} ${ariaLabel} ${className} ${id}`;
        const isVisible = await btn.isVisible().catch(() => false);
        if (!isVisible) continue;

        if (action === 'accept' &&
            /accept|zustimmen|einverstanden|alle.*zulassen|ok|verstanden|akzeptieren|allow.*all/i.test(allText)) {
          await btn.click(); await page.waitForTimeout(2000); return true;
        }

        if (action === 'reject' &&
            /reject|ablehnen|nur.*notwendig|minimal|essential.*only|necessary.*only|decline/i.test(allText)) {
          await btn.click(); await page.waitForTimeout(2000); return true;
        }
      }

      return false;
    } catch (error) {
      console.log(`Consent handling failed: ${error.message}`);
      return false;
    }
  }

  // Tag-Erkennung (Netzwerk + DOM)
  async checkMarketingTagsDeep(page, requestLog) {
    const networkBasedDetection = {
      hasGA4:        requestLog.some(r => /gtag\/js\?id=G-|google-analytics\.com\/g\/collect/.test(r.url)),
      hasUA:         requestLog.some(r => /google-analytics\.com\/analytics\.js|google-analytics\.com\/collect/.test(r.url)),
      hasGTM:        requestLog.some(r => /googletagmanager\.com\/gtm\.js/.test(r.url)),
      hasGoogleAds:  requestLog.some(r => /googleadservices\.com|googlesyndication\.com/.test(r.url)),
      hasMetaPixel:  requestLog.some(r => /connect\.facebook\.net|facebook\.com\/tr/.test(r.url)),
      hasTikTokPixel:requestLog.some(r => /analytics\.tiktok\.com/.test(r.url)),
      hasHotjar:     requestLog.some(r => /static\.hotjar\.com/.test(r.url)),
      hasCrazyEgg:   requestLog.some(r => /script\.crazyegg\.com/.test(r.url))
    };

    const domBasedDetection = await page.evaluate(() => {
      const scripts = [...document.scripts];

      const hasGA4 = scripts.some(s => /gtag\/js\?id=G-/.test(s.src)) || typeof window.gtag !== 'undefined';
      const hasUA  = scripts.some(s => /google-analytics\.com\/analytics\.js/.test(s.src)) || typeof window.ga   !== 'undefined';
      const hasGTM = scripts.some(s => /googletagmanager\.com\/gtm\.js/.test(s.src)) || !!window.dataLayer;
      const hasGoogleAds = scripts.some(s => /googleadservices\.com|googlesyndication\.com/.test(s.src));
      const hasMetaPixel = typeof window.fbq !== 'undefined' || scripts.some(s => /connect\.facebook\.net/.test(s.src));
      const hasTikTokPixel = typeof window.ttq !== 'undefined' || scripts.some(s => /analytics\.tiktok\.com/.test(s.src));
      const hasHotjar = typeof window.hj !== 'undefined' || scripts.some(s => /static\.hotjar\.com/.test(s.src));
      const hasCrazyEgg = typeof window.CE !== 'undefined' || scripts.some(s => /script\.crazyegg\.com/.test(s.src));

      const dlEvents = Array.isArray(window.dataLayer)
        ? window.dataLayer.map(e => e && e.event).filter(Boolean)
        : [];

      const iframes = [...document.querySelectorAll('iframe')];
      const hasGoogleAdsFrame = iframes.some(iframe => /googleadservices|googlesyndication/.test(iframe.src));
      const hasMetaFrame = iframes.some(iframe => /facebook\.com/.test(iframe.src));

      return {
        hasGA4, hasUA, hasGTM,
        hasGoogleAds: hasGoogleAds || hasGoogleAdsFrame,
        hasMetaPixel: hasMetaPixel || hasMetaFrame,
        hasTikTokPixel, hasHotjar, hasCrazyEgg,
        dlEvents,
        scriptCount: scripts.length,
        iframeCount: iframes.length
      };
    });

    return {
      hasGA4:        networkBasedDetection.hasGA4        || domBasedDetection.hasGA4,
      hasUA:         networkBasedDetection.hasUA         || domBasedDetection.hasUA,
      hasGTM:        networkBasedDetection.hasGTM        || domBasedDetection.hasGTM,
      hasGoogleAds:  networkBasedDetection.hasGoogleAds  || domBasedDetection.hasGoogleAds,
      hasMetaPixel:  networkBasedDetection.hasMetaPixel  || domBasedDetection.hasMetaPixel,
      hasTikTokPixel:networkBasedDetection.hasTikTokPixel|| domBasedDetection.hasTikTokPixel,
      hasHotjar:     networkBasedDetection.hasHotjar     || domBasedDetection.hasHotjar,
      hasCrazyEgg:   networkBasedDetection.hasCrazyEgg   || domBasedDetection.hasCrazyEgg,
      dlEvents: domBasedDetection.dlEvents,
      advanced: {
        networkDetection: networkBasedDetection,
        domDetection: domBasedDetection
      }
    };
  }

  // Consent-Compliance-Auswertung
  analyzeConsentCompliance() {
    const { withoutConsent, withConsent, withReject } = this.results;

    this.marketingTags = [
      this.analyzeTagCompliance('Google Analytics 4', 'hasGA4'),
      this.analyzeTagCompliance('Google Analytics Universal', 'hasUA'),
      this.analyzeTagCompliance('Google Tag Manager', 'hasGTM'),
      this.analyzeTagCompliance('Google Ads Tracking', 'hasGoogleAds'),
      this.analyzeTagCompliance('Meta Pixel (Facebook/Instagram)', 'hasMetaPixel'),
      this.analyzeTagCompliance('TikTok Pixel', 'hasTikTokPixel'),
      this.analyzeTagCompliance('Hotjar', 'hasHotjar'),
      this.analyzeTagCompliance('CrazyEgg', 'hasCrazyEgg')
    ].filter(tag => tag.relevant);
  }

  analyzeTagCompliance(tagName, tagProperty) {
    const { withoutConsent, withConsent, withReject } = this.results;

    const noConsent = withoutConsent?.marketingTags?.[tagProperty] || false;
    const withAccept = withConsent?.marketingTags?.[tagProperty] || false;
    const withRejectConsent = withReject?.marketingTags?.[tagProperty] || false;

    if (!noConsent && !withAccept && !withRejectConsent) {
      return { relevant: false };
    }

    let compliance = 'unknown';
    let impact = '';
    let gdprRisk = 'low';

    if (!noConsent && withAccept && !withRejectConsent) {
      compliance = 'perfect';
      impact = `✅ ${tagName} respektiert Consent perfekt - DSGVO-konform`;
      gdprRisk = 'none';
    } else if (noConsent && withAccept && !withRejectConsent) {
      compliance = 'good';
      impact = `🟡 ${tagName} lädt vor Consent, aber stoppt bei Ablehnung`;
      gdprRisk = 'low';
    } else if (noConsent && withAccept && withRejectConsent) {
      compliance = 'bad';
      impact = `🚨 ${tagName} ignoriert Consent komplett - DSGVO-Verstoß!`;
      gdprRisk = 'high';
    } else if (!noConsent && !withAccept && !withRejectConsent) {
      compliance = 'missing';
      impact = `❌ ${tagName} nicht installiert - kompletter Tracking-Verlust`;
      gdprRisk = 'none';
    } else {
      compliance = 'inconsistent';
      impact = `🤔 ${tagName} verhält sich inkonsistent - manuelle Prüfung nötig`;
      gdprRisk = 'medium';
    }

    return {
      relevant: true,
      name: tagName,
      property: tagProperty,
      withoutConsent: noConsent,
      withAccept: withAccept,
      withReject: withRejectConsent,
      compliance,
      impact,
      gdprRisk,
      businessImpact: this.getBusinessImpact(tagName, compliance)
    };
  }

  getBusinessImpact(tagName, compliance) {
    const impacts = {
      'Google Analytics 4': {
        perfect: 'Besucherdaten werden DSGVO-konform erfasst',
        good: 'Tracking läuft, aber rechtliches Risiko',
        bad: 'Abmahnrisiko durch Consent-Ignorierung',
        missing: 'Keine Besucherdaten → Marketing fliegt blind'
      },
      'Google Ads Tracking': {
        perfect: 'Conversion-Tracking DSGVO-konform',
        good: 'ROI messbar, aber rechtliches Risiko',
        bad: 'Abmahnrisiko + ungenaue Kampagnen-Daten',
        missing: 'Werbebudget-Verschwendung durch fehlende Messung'
      },
      'Meta Pixel (Facebook/Instagram)': {
        perfect: 'Social Media ROI DSGVO-konform messbar',
        good: 'Retargeting funktioniert, rechtliches Risiko',
        bad: 'Abmahnrisiko bei Facebook/Instagram Ads',
        missing: 'Facebook/Instagram Ads laufen blind'
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
      'googleadservices': '🎯 Google Ads Conversion-Tracking blockiert - ROI nicht messbar',
      'connect.facebook.net': '📱 Meta Pixel blockiert - Facebook/Instagram Ads Performance unbekannt',
      'googletagmanager': '📊 Google Tag Manager blockiert - alle Marketing-Tags betroffen',
      'analytics.tiktok.com': '🎵 TikTok Pixel blockiert - TikTok Ads ROI unbekannt',
      'static.hotjar.com': '🖱️ Hotjar Heatmap-Tracking blockiert',
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
      return `🎯 Google Ads (${status}) - Conversion-Tracking gestört`;
    }
    if (url.includes('facebook.net') || url.includes('meta')) {
      return `📱 Meta Pixel (${status}) - Social Media ROI unbekannt`;
    }
    if (url.includes('analytics') && url.includes('google')) {
      return `📊 Google Analytics (${status}) - Besucherdaten verloren`;
    }
    if (url.includes('tiktok')) {
      return `🎵 TikTok Pixel (${status}) - TikTok Kampagnen unoptimiert`;
    }
    if (url.includes('hotjar')) {
      return `🖱️ Hotjar (${status}) - Nutzerverhalten-Analyse nicht möglich`;
    }
    return `⚠️ Marketing-Tool blockiert (${status})`;
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
    if (errorMessage.includes('static.hotjar.com')) {
      return `CSP erweitern:\nContent-Security-Policy:\n  script-src ... https://static.hotjar.com;\n  connect-src ... https://static.hotjar.com;`;
    }
    if (errorMessage.includes('Content Security Policy')) {
      return 'CSP-Header überprüfen und relevante Marketing-Domains whitelisten';
    }
    return 'Entwickler-Konsole öffnen, Fehlerstack analysieren, betroffene Datei reparieren';
  }

  suggestFixForUrl(url, error) {
    try {
      const domain = new URL(url).hostname;
      if (error?.includes('CSP') || error?.includes('BLOCKED')) {
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
      const directive = violation.violatedDirective.split(' ')[0];
      return `CSP-Directive erweitern:\nContent-Security-Policy:\n  ${directive} ... https://${domain};`;
    } catch {
      return `CSP-Policy überprüfen: ${violation.violatedDirective} für ${violation.blockedURI}`;
    }
  }

  // Ergebnis zusammenbauen
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

// =====================================================
//                      API
// =====================================================
app.post('/scan', async (req, res) => {
  const { url } = req.body || {};
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

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: VERSION,
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/version', (req, res) => {
  res.json({
    version: VERSION,
    buildTime: new Date().toISOString(),
    nodeVersion: process.version
  });
});

// =====================================================
//                   Frontend (UI)
//  — Claudes UX-Verbesserungen, ohne Evidence-Sektion
// =====================================================
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Ultimate Website Scanner - DSGVO & Marketing Check</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
    .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 25px 50px rgba(0,0,0,0.15); overflow: hidden; }
    .header { background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%); color: white; padding: 50px 30px; text-align: center; }
    .header h1 { font-size: 2.5em; margin-bottom: 20px; font-weight: 700; line-height: 1.2; }
    .header p { opacity: 0.9; font-size: 1.1em; margin-bottom: 15px; max-width: 800px; margin-left: auto; margin-right: auto; }
    .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 25px; padding: 30px; background: rgba(255,255,255,0.1); margin-top: 30px; border-radius: 12px; }
    .feature { text-align: center; padding: 20px; }
    .feature-icon { font-size: 2.5em; margin-bottom: 15px; }
    .feature h3 { margin-bottom: 10px; font-size: 1.2em; }
    .feature p { font-size: 0.95em; opacity: 0.9; }
    .form-section { padding: 50px; }
    .input-group { margin-bottom: 30px; }
    label { display: block; margin-bottom: 12px; font-weight: 600; color: #2d3748; font-size: 1.1em; }
    .url-input-container { position: relative; }
    input[type="url"] { width: 100%; padding: 20px; border: 2px solid #e2e8f0; border-radius: 12px; font-size: 16px; transition: all 0.3s; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    input[type="url"]:focus { border-color: #667eea; outline: none; box-shadow: 0 0 0 3px rgba(102,126,234,0.1); }
    input[type="url"].valid { border-color: #48bb78; }
    input[type="url"].invalid { border-color: #f56565; }
    .url-validation { font-size: 0.85em; margin-top: 8px; padding: 5px 0; min-height: 20px; }
    .url-validation.valid { color: #48bb78; }
    .url-validation.invalid { color: #f56565; }
    .scan-button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 22px 50px; border-radius: 12px; font-size: 18px; font-weight: 600; cursor: pointer; width: 100%; transition: all 0.3s; box-shadow: 0 4px 15px rgba(102,126,234,0.4); position: relative; overflow: hidden; }
    .scan-button:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(102,126,234,0.6); }
    .scan-button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: 0 4px 15px rgba(102,126,234,0.2); }
    .quick-demo { text-align: center; margin: 20px 0; padding: 15px; background: #f7fafc; border-radius: 8px; border: 1px solid #e2e8f0; }
    .demo-button { background: #4299e1; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 0.9em; cursor: pointer; margin: 0 5px; }
    .loading { display: none; text-align: center; padding: 40px; color: #667eea; background: #f8f9fa; margin: 20px; border-radius: 12px; }
    .progress-container { margin: 25px 0; }
    .progress-bar { width: 100%; height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; position: relative; }
    .progress-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); width: 0%; transition: width 0.5s ease; border-radius: 4px; position: relative; }
    .loading-steps { display: flex; justify-content: space-between; margin-top: 15px; font-size: 0.85em; }
    .loading-step { padding: 8px 12px; background: #e2e8f0; border-radius: 15px; transition: all 0.3s; }
    .loading-step.active { background: #667eea; color: white; transform: scale(1.05); }
    .loading-step.completed { background: #48bb78; color: white; }
    .results { display: none; padding: 0 50px 50px; }
    .risk-indicator { padding: 25px; border-radius: 12px; margin-bottom: 30px; font-weight: 600; text-align: center; }
    .risk-high { background: linear-gradient(135deg, #fed7d7 0%, #feb2b2 100%); color: #c53030; border: 2px solid #fc8181; }
    .risk-medium { background: linear-gradient(135deg, #fefcbf 0%, #faf089 100%); color: #d69e2e; border: 2px solid #f6e05e; }
    .risk-low { background: linear-gradient(135deg, #c6f6d5 0%, #9ae6b4 100%); color: #2f855a; border: 2px solid #68d391; }
    .section { margin-bottom: 30px; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .section-header { background: linear-gradient(135deg, #f8f9fa 0%, #e2e8f0 100%); padding: 20px; font-weight: 600; display: flex; justify-content: space-between; align-items: center; font-size: 1.1em; cursor: pointer; user-select: none; }
    .badge { background: #4299e1; color: white; padding: 6px 12px; border-radius: 15px; font-size: 0.85em; font-weight: 500; display: inline-flex; align-items: center; gap: 5px; }
    .badge.high { background: #e53e3e; } .badge.medium { background: #d69e2e; } .badge.critical { background: #9f1239; }
    .section-content { padding: 25px; }
    .compliance-item { padding: 20px; margin: 15px 0; border-radius: 10px; border-left: 5px solid; }
    .compliance-perfect { background: #f0fff4; border-left-color: #38a169; }
    .compliance-good { background: #fefcbf; border-left-color: #d69e2e; }
    .compliance-bad { background: #fff5f5; border-left-color: #e53e3e; }
    .compliance-missing { background: #f7fafc; border-left-color: #a0aec0; }
    .compliance-inconsistent { background: #fdf2e9; border-left-color: #ed8936; }
    .consent-matrix { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-top: 15px; font-size: 0.9em; background: #f8f9fa; padding: 15px; border-radius: 8px; }
    .consent-result { text-align: center; padding: 10px; border-radius: 6px; font-weight: 500; }
    .consent-pass { background: #c6f6d5; color: #2f855a; }
    .consent-fail { background: #fed7d7; color: #c53030; }
    .issue-item { background: #fff5f5; border: 1px solid #feb2b2; border-radius: 10px; padding: 20px; margin: 15px 0; }
    .tech-details { background: #f7fafc; padding: 15px; border-radius: 8px; margin-top: 12px; font-size: 0.95em; color: #4a5568; font-family: 'Monaco','Menlo',monospace; }
    .fix-suggestion { background: #e6fffa; border: 1px solid #4fd1c7; padding: 15px; border-radius: 8px; margin-top: 12px; font-family: 'Monaco','Menlo',monospace; font-size: 0.9em; position: relative; }
    .copy-button { position: absolute; top: 8px; right: 8px; background: #319795; color: white; border: none; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; cursor: pointer; }
    @media (max-width: 768px) {
      .container { margin: 10px; }
      .header { padding: 30px 20px; }
      .header h1 { font-size: 1.8em; }
      .form-section, .results { padding: 30px 20px; }
      .features { grid-template-columns: 1fr; gap: 15px; padding: 20px; }
      .consent-matrix { grid-template-columns: 1fr; gap: 8px; }
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
        <div class="feature"><div class="feature-icon">🍪</div><h3>Cookie-Banner-Test</h3><p>3-Wege-Analyse: ohne Consent, mit Accept, mit Reject</p></div>
        <div class="feature"><div class="feature-icon">🔒</div><h3>CSP-Violations</h3><p>Findet blockierte Marketing-Scripts durch Sicherheitsrichtlinien</p></div>
        <div class="feature"><div class="feature-icon">📊</div><h3>DSGVO-Compliance</h3><p>Überprüft Google Analytics, Meta Pixel, TikTok & mehr</p></div>
        <div class="feature"><div class="feature-icon">💰</div><h3>Business Impact</h3><p>Zeigt konkrete Umsatz-Verluste und Lösungsansätze</p></div>
      </div>
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

        <div class="quick-demo">
          <p><strong>Schnelltest:</strong></p>
          <button type="button" class="demo-button" data-url="https://example.com">Example.com</button>
          <button type="button" class="demo-button" data-url="https://google.com">Google.com</button>
          <button type="button" class="demo-button" data-url="https://facebook.com">Facebook.com</button>
        </div>

        <button type="submit" class="scan-button" id="scanBtn">🔍 Vollständigen 3-Session-Scan starten</button>
      </form>

      <div class="loading" id="loading">
        <h3>⏳ Führe umfassende DSGVO & Marketing-Analyse durch...</h3>
        <div class="progress-container">
          <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
          <div class="loading-steps">
            <div class="loading-step" id="step1">1. Ohne Consent</div>
            <div class="loading-step" id="step2">2. Mit Accept</div>
            <div class="loading-step" id="step3">3. Mit Reject</div>
            <div class="loading-step" id="step4">4. Analyse</div>
          </div>
        </div>
        <p id="loadingText">Initialisiere Browser...</p>
        <p><small>Das kann 60–90 Sekunden dauern</small></p>
      </div>
    </div>

    <div class="results" id="results"></div>

    <div class="footer">
      <p>Powered by Playwright Browser Automation • Version ${VERSION}</p>
      <p><small>Sichere Analyse ohne Datenspeicherung • Made in Germany</small></p>
    </div>
  </div>

  <script>
    // URL validation
    const urlInput = document.getElementById('url');
    const urlValidation = document.getElementById('urlValidation');

    urlInput.addEventListener('input', (e) => {
      const url = e.target.value;
      if (!url) {
        urlInput.className = '';
        urlValidation.textContent = '';
        urlValidation.className = 'url-validation';
        return;
      }
      try {
        const u = new URL(url);
        if (u.protocol === 'http:' || u.protocol === 'https:') {
          urlInput.className = 'valid';
          urlValidation.textContent = '✅ Gültige URL';
          urlValidation.className = 'url-validation valid';
        } else {
          throw new Error('Nur HTTP/HTTPS URLs');
        }
      } catch (error) {
        urlInput.className = 'invalid';
        urlValidation.textContent = '❌ Ungültige URL (https://example.com verwenden)';
        urlValidation.className = 'url-validation invalid';
      }
    });

    // Demo buttons
    document.querySelectorAll('.demo-button').forEach(btn => {
      btn.addEventListener('click', () => {
        urlInput.value = btn.dataset.url;
        urlInput.dispatchEvent(new Event('input'));
      });
    });

    // Form submission
    document.getElementById('scanForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      const url = document.getElementById('url').value;
      const loading = document.getElementById('loading');
      const results = document.getElementById('results');
      const scanBtn = document.getElementById('scanBtn');
      const progressFill = document.getElementById('progressFill');
      const loadingText = document.getElementById('loadingText');

      // UI Updates
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning läuft...';
      loading.style.display = 'block';
      results.style.display = 'none';

      // Reset progress
      progressFill.style.width = '0%';
      document.querySelectorAll('.loading-step').forEach(step => step.classList.remove('active','completed'));

      // Pseudo-Progress
      const steps = [
        { p: 5,  t: 'Browser wird gestartet...', id: null },
        { p: 15, t: 'Session 1/3: Ohne Consent laden...', id: 'step1' },
        { p: 35, t: 'Session 1/3: Marketing-Tags analysieren...', id: 'step1' },
        { p: 45, t: 'Session 2/3: Mit akzeptiertem Consent...', id: 'step2' },
        { p: 65, t: 'Session 2/3: Consent-Verhalten prüfen...', id: 'step2' },
        { p: 75, t: 'Session 3/3: Mit abgelehntem Consent...', id: 'step3' },
        { p: 85, t: 'Session 3/3: DSGVO-Compliance bewerten...', id: 'step3' },
        { p: 95, t: 'Consent-Matrix analysieren...', id: 'step4' },
        { p: 100,t: 'Abschlussbericht erstellen...', id: 'step4' }
      ];
      let i = 0;
      const iv = setInterval(() => {
        if (i < steps.length) {
          const s = steps[i++];
          progressFill.style.width = s.p + '%';
          loadingText.textContent = s.t;
          if (s.id) {
            document.querySelectorAll('.loading-step').forEach(s2 => s2.classList.remove('active'));
            const el = document.getElementById(s.id);
            if (el) {
              el.classList.add('active');
              const num = parseInt(s.id.replace('step',''));
              for (let k=1;k<num;k++){
                const prev = document.getElementById('step'+k);
                prev && prev.classList.add('completed');
              }
            }
          }
        }
      }, 8000);

      try {
        const resp = await fetch('/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
        const data = await resp.json();

        clearInterval(iv);
        progressFill.style.width = '100%';
        loadingText.textContent = 'Scan abgeschlossen!';
        document.querySelectorAll('.loading-step').forEach(s => { s.classList.remove('active'); s.classList.add('completed'); });

        setTimeout(() => {
          if (resp.ok) displayResults(data);
          else throw new Error(data.error || data.details);
        }, 1000);
      } catch (error) {
        clearInterval(iv);
        results.innerHTML = \`
          <div class="section">
            <div class="section-content">
              <h3 style="color: #e53e3e;">❌ Scan fehlgeschlagen</h3>
              <p><strong>Fehler:</strong> \${error.message}</p>
              <div class="tech-details">
                <strong>Mögliche Ursachen:</strong><br>
                • Website nicht erreichbar oder blockiert Scanner<br>
                • Timeout nach 60+ Sekunden<br>
                • Temporäre Netzwerkprobleme<br>
                • Aggressive Bot-Protection
              </div>
              <p style="margin-top: 15px;"><strong>Lösungsvorschlag:</strong> Bitte später erneut versuchen oder eine andere URL testen.</p>
            </div>
          </div>
        \`;
        results.style.display = 'block';
      }

      // Reset
      loading.style.display = 'none';
      scanBtn.disabled = false;
      scanBtn.textContent = '🔍 Vollständigen 3-Session-Scan starten';
    });

    function displayResults(data) {
      const results = document.getElementById('results');
      const marketingTags = data.summary.marketingTags || [];
      const riskLevel = calculateOverallRisk(data);

      results.innerHTML = \`
        <div class="risk-indicator risk-\${riskLevel.level}">
          <h3>\${riskLevel.icon} \${riskLevel.text}</h3>
          <p><strong>\${data.scannedUrl}</strong></p>
          <p>\${data.summary.totalIssues} Issues • \${marketingTags.length} Marketing-Tags analysiert • \${data.summary.highPriorityIssues} kritische Probleme</p>
          <small>Gescannt am: \${data.timestamp}</small>
        </div>

        <div class="section">
          <div class="section-header" onclick="toggleSection(this)">
            🍪 Cookie-Consent Compliance Matrix
            <span class="badge">3-Wege-Test ▼</span>
          </div>
          <div class="section-content">
            \${marketingTags.length > 0 ? marketingTags.map(tag => \`
              <div class="compliance-item compliance-\${tag.compliance}">
                <strong>\${tag.name}:</strong> \${tag.impact}
                <div class="consent-matrix">
                  <div class="consent-result \${tag.withoutConsent ? 'consent-fail' : 'consent-pass'}">
                    <div><strong>Ohne Consent</strong></div>
                    <div>\${tag.withoutConsent ? '❌ Lädt' : '✅ Blockiert'}</div>
                  </div>
                  <div class="consent-result \${tag.withAccept ? 'consent-pass' : 'consent-fail'}">
                    <div><strong>Mit Accept</strong></div>
                    <div>\${tag.withAccept ? '✅ Lädt' : '❌ Blockiert'}</div>
                  </div>
                  <div class="consent-result \${tag.withReject ? 'consent-fail' : 'consent-pass'}">
                    <div><strong>Mit Reject</strong></div>
                    <div>\${tag.withReject ? '❌ Lädt' : '✅ Blockiert'}</div>
                  </div>
                </div>
                <div style="margin-top: 15px; padding: 10px; background: rgba(0,0,0,0.05); border-radius: 6px;">
                  <div><strong>💼 Business-Impact:</strong> \${tag.businessImpact}</div>
                  <div><strong>⚖️ DSGVO-Risiko:</strong> \${getGDPRRiskText(tag.gdprRisk)}</div>
                </div>
              </div>
            \`).join('') : '<p>Keine Marketing-Tags gefunden oder alle Sessions fehlgeschlagen.</p>'}
          </div>
        </div>

        \${data.details.errors.length > 0 ? \`
        <div class="section">
          <div class="section-header" onclick="toggleSection(this)">
            ⚠️ JavaScript & Console Errors
            <span class="badge high">\${data.details.errors.length} ▼</span>
          </div>
          <div class="section-content">
            \${data.details.errors.slice(0, 10).map(error => \`
              <div class="issue-item">
                <div><strong>🎯 Business-Impact:</strong> \${error.translation}</div>
                <div class="tech-details">
                  <strong>Technisch:</strong> \${error.message}<br>
                  <strong>Session:</strong> \${error.consentMode} | <strong>Typ:</strong> \${error.type}
                </div>
                <div class="fix-suggestion">
                  <strong>💡 Lösungsvorschlag:</strong> \${error.techFix}
                  <button class="copy-button" onclick="copyToClipboard('\${error.techFix}')">Kopieren</button>
                </div>
              </div>
            \`).join('')}
            \${data.details.errors.length > 10 ? \`<p><em>... und \${data.details.errors.length - 10} weitere Fehler</em></p>\` : ''}
          </div>
        </div>
        \` : ''}

        \${data.details.networkIssues.length > 0 ? \`
        <div class="section">
          <div class="section-header" onclick="toggleSection(this)">
            🌐 Netzwerk & Loading Issues
            <span class="badge medium">\${data.details.networkIssues.length} ▼</span>
          </div>
          <div class="section-content">
            \${data.details.networkIssues.slice(0, 12).map(issue => \`
              <div class="issue-item">
                <div><strong>🎯 Business-Impact:</strong> \${issue.translation}</div>
                <div class="tech-details">
                  <strong>URL:</strong> \${issue.url}<br>
                  <strong>Status:</strong> \${issue.status} | <strong>Session:</strong> \${issue.consentMode}
                </div>
                <div class="fix-suggestion">
                  <strong>💡 Lösungsvorschlag:</strong> \${issue.techFix}
                  <button class="copy-button" onclick="copyToClipboard('\${issue.techFix}')">Kopieren</button>
                </div>
              </div>
            \`).join('')}
            \${data.details.networkIssues.length > 12 ? \`<p><em>... und \${data.details.networkIssues.length - 12} weitere Issues</em></p>\` : ''}
          </div>
        </div>
        \` : ''}

        \${data.details.cspViolations.length > 0 ? \`
        <div class="section">
          <div class="section-header" onclick="toggleSection(this)">
            🔒 CSP-Violations (Content Security Policy)
            <span class="badge critical">\${data.details.cspViolations.length} ▼</span>
          </div>
          <div class="section-content">
            <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #d69e2e;">
              <strong>⚠️ Kritisch für Marketing:</strong> CSP-Violations blockieren oft wichtige Marketing-Scripts wie Google Analytics, Facebook Pixel etc.
            </div>
            \${data.details.cspViolations.map(v => \`
              <div class="issue-item">
                <div><strong>🎯 Business-Impact:</strong> \${v.translation}</div>
                <div class="tech-details">
                  <strong>Violation:</strong> \${v.message}<br>
                  <strong>Session:</strong> \${v.consentMode}
                </div>
                <div class="fix-suggestion">
                  <strong>💡 CSP-Fix (für Entwickler):</strong> \${v.techFix}
                  <button class="copy-button" onclick="copyToClipboard('\${v.techFix}')">Kopieren</button>
                </div>
              </div>
            \`).join('')}
          </div>
        </div>
        \` : ''}

        <div class="section">
          <div class="section-header" onclick="toggleSection(this)">
            💡 Priorisierte Handlungsempfehlungen
            <span class="badge">Roadmap ▼</span>
          </div>
          <div class="section-content">
            \${generateActionPlan(data)}
          </div>
        </div>

        <div class="section">
          <div class="section-header" onclick="toggleSection(this)">
            📋 Scan-Details & Technische Infos
            <span class="badge">Debug ▼</span>
          </div>
          <div class="section-content" style="display:none;">
            <div class="tech-details">
              <strong>Scan-Version:</strong> \${data.version}<br>
              <strong>Gescannt:</strong> \${data.timestamp}<br>
              <strong>URL:</strong> \${data.scannedUrl}<br>
              <strong>Sessions:</strong> 3 (ohne Consent, mit Accept, mit Reject)<br>
              <strong>Gesamt Issues:</strong> \${data.summary.totalIssues}<br>
              <strong>Kritische Issues:</strong> \${data.summary.highPriorityIssues}
            </div>
          </div>
        </div>
      \`;

      results.style.display = 'block';
    }

    function calculateOverallRisk(data) {
      const highPriorityIssues = data.summary.highPriorityIssues || 0;
      const marketingTags = data.summary.marketingTags || [];
      const badCompliance = marketingTags.filter(tag => tag.compliance === 'bad').length;
      const missingTags = marketingTags.filter(tag => tag.compliance === 'missing').length;
      const cspViolations = data.details.cspViolations?.length || 0;

      if (highPriorityIssues >= 5 || badCompliance >= 3 || cspViolations >= 3) {
        return { level: 'high', icon: '🚨', text: 'Kritisches Risiko - Sofortiger Handlungsbedarf!' };
      } else if (highPriorityIssues >= 2 || badCompliance >= 1 || cspViolations >= 1 || missingTags >= 3) {
        return { level: 'medium', icon: '⚠️', text: 'Mittleres Risiko - Optimierung dringend empfohlen' };
      } else if (highPriorityIssues >= 1 || missingTags >= 1) {
        return { level: 'medium', icon: '🟡', text: 'Verbesserungspotenzial vorhanden' };
      } else {
        return { level: 'low', icon: '✅', text: 'Guter Zustand - Setup funktioniert solide' };
      }
    }

    function getGDPRRiskText(risk) {
      const risks = { 'none':'✅ Kein Risiko','low':'🟡 Geringes Risiko','medium':'🟠 Mittleres Risiko','high':'🔴 Hohes Abmahnrisiko!' };
      return risks[risk] || '🤔 Unbekannt';
    }

    function generateActionPlan(data) {
      const actions = [];
      const cspCount = data.details.cspViolations?.length || 0;
      const badTags = data.summary.marketingTags?.filter(tag => tag.compliance === 'bad') || [];
      const missingTags = data.summary.marketingTags?.filter(tag => tag.compliance === 'missing') || [];
      const highErrors = data.details.errors?.filter(e => e.priority === 'high' || e.priority === 'critical') || [];

      if (cspCount > 0) actions.push(\`<div class="compliance-item compliance-bad"><strong>🔥 PRIORITÄT 1 - CSP-Violations beheben (\${cspCount}x)</strong><br>CSP-Header überarbeiten und Marketing-Domains whitelisten.</div>\`);
      if (badTags.length > 0) actions.push(\`<div class="compliance-item compliance-bad"><strong>⚖️ PRIORITÄT 2 - DSGVO-Verstöße beheben (\${badTags.length}x)</strong><br>Tags: \${badTags.map(t => t.name).join(', ')} ignorieren Consent. CMP-Konfiguration prüfen.</div>\`);
      if (missingTags.length > 0) actions.push(\`<div class="compliance-item compliance-missing"><strong>📊 PRIORITÄT 3 - Fehlende Marketing-Tags implementieren (\${missingTags.length}x)</strong><br>Keine Daten = keine Optimierung. Tags: \${missingTags.map(t => t.name).join(', ')}</div>\`);
      if (highErrors.length > 0) actions.push(\`<div class="compliance-item compliance-good"><strong>🔧 PRIORITÄT 4 - JavaScript-Fehler beheben (\${highErrors.length}x)</strong><br>Fehler können Marketing-Performance beeinträchtigen. Entwickler-Konsole prüfen.</div>\`);
      actions.push(\`<div class="compliance-item compliance-perfect"><strong>🔄 PRIORITÄT 5 - Monitoring einrichten</strong><br>Wöchentliche Scans automatisieren (Regressionen früh erkennen).</div>\`);
      return actions.join('');
    }

    function toggleSection(header) {
      const content = header.nextElementSibling;
      const badge = header.querySelector('.badge');
      if (content.style.display === 'none' || !content.style.display) {
        content.style.display = 'block';
        badge.textContent = badge.textContent.replace('▼','▲');
      } else {
        content.style.display = 'none';
        badge.textContent = badge.textContent.replace('▲','▼');
      }
    }

    function copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        alert('✓ Kopiert');
      });
    }
  </script>
</body>
</html>
  `);
});

// ---------------- Server start ----------------
app.listen(PORT, () => {
  console.log(`🚀 Website Scanner running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔍 Scanner UI: http://localhost:${PORT}/`);
});
