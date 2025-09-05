// server.js
import express from 'express';
import { chromium } from 'playwright';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import helmet from 'helmet';

const app = express();
app.set('trust proxy', 1); // Render/Proxy

const PORT = process.env.PORT || 3000;
const VERSION = process.env.GIT_SHA || '2.2.3';

// ─────────────────────────────────────────────────────────────────────────────
// Security & Middleware
// ─────────────────────────────────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate Limit nur auf /scan anwenden
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Rate limit exceeded. Max 20 scans per 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/scan', limiter);

// ─────────────────────────────────────────────────────────────────────────────
// Scanner-Klasse (bewährt, mit verbessertem Logging)
// ─────────────────────────────────────────────────────────────────────────────
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

      // Privatnetze blocken (IPv4)
      if (/(^|\.)(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)/.test(hostname)) {
        throw new Error('Private/internal IPs not allowed');
      }
      // IPv6 Loopback
      if (/^\[?::1\]?$/.test(hostname)) {
        throw new Error('Loopback IPv6 not allowed');
      }
      // IPv4 im Klartext: Private Ranges prüfen
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

  async scanWithRetry(url, maxRetries = 2) {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await this.scan(url);
      } catch (error) {
        if (attempt === maxRetries) throw error;
        console.warn(`Retry ${attempt + 1}/${maxRetries} for ${url}: ${error.message}`);
        await new Promise(r => setTimeout(r, 3000 * (attempt + 1))); // leichter Backoff
      }
    }
  }

  async scan(url) {
    this.reset();
    this.validateUrl(url);

    console.log(`🔍 Starting comprehensive scan of ${url}`);
    console.log('Launching Chromium…');

    let browser;
    try {
      browser = await chromium.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-web-security',
          '--disable-features=VizDisplayCompositor'
        ]
      });
    } catch (e) {
      console.error('Chromium launch failed:', e);
      throw new Error('Chromium konnte nicht gestartet werden: ' + (e?.message || e));
    }

    try {
      // A: Ohne Consent
      console.log('🚫 Run A: Scanning without consent…');
      this.results.withoutConsent = await this.runSingleScan(browser, url, 'no-consent');

      // B: Mit Consent akzeptiert
      console.log('✅ Run B: Scanning with consent accepted…');
      this.results.withConsent = await this.runSingleScan(browser, url, 'accept');

      // C: Mit Consent abgelehnt
      console.log('❌ Run C: Scanning with consent rejected…');
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
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      viewport: { width: 1920, height: 1080 },
      ignoreHTTPSErrors: true
    });

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
      consentMode
    };

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

    page.on('console', msg => {
      if (msg.type() === 'error') {
        scanData.errors.push({
          type: 'Console Error',
          message: msg.text(),
          location: msg.location?.(),
          priority: this.classifyErrorPriority(msg.text()),
          translation: this.translateError(msg.text()),
          techFix: this.suggestFix(msg.text()),
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
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });

      if (consentMode === 'accept') {
        await this.handleConsent(page, 'accept');
      } else if (consentMode === 'reject') {
        await this.handleConsent(page, 'reject');
      }

      await page.evaluate(() => { window.scrollTo(0, document.body.scrollHeight); });
      await Promise.race([
        page.waitForLoadState('networkidle', { timeout: 3000 }).catch(() => {}),
        page.waitForTimeout(1500)
      ]);

      scanData.marketingTags = await this.checkMarketingTagsDeep(page, scanData.requestLog);

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
        domain
      },
      { name: 'cookielawinfo-checkbox-necessary', value: 'yes', domain },
      { name: 'cookielawinfo-checkbox-analytics', value: acceptAll ? 'yes' : 'no', domain },
      { name: 'cookielawinfo-checkbox-advertisement', value: acceptAll ? 'yes' : 'no', domain }
    ];
    for (const cookie of consentCookies) {
      try { await context.addCookies([cookie]); } catch {}
    }
  }

  async handleConsent(page, action) {
    try {
      await page.waitForTimeout(2000);
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
          await btn.click();
          await page.waitForTimeout(2000);
          return true;
        }
        if (action === 'reject' &&
            /reject|ablehnen|nur.*notwendig|minimal|essential.*only|necessary.*only/i.test(allText)) {
          await btn.click();
          await page.waitForTimeout(2000);
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
    const networkBasedDetection = {
      hasGA4: requestLog.some(r => /gtag\/js\?id=G-|google-analytics\.com\/g\/collect/.test(r.url)),
      hasUA: requestLog.some(r => /google-analytics\.com\/analytics\.js|google-analytics\.com\/collect/.test(r.url)),
      hasGTM: requestLog.some(r => /googletagmanager\.com\/gtm\.js/.test(r.url)),
      hasGoogleAds: requestLog.some(r => /googleadservices\.com|googlesyndication\.com/.test(r.url)),
      hasMetaPixel: requestLog.some(r => /connect\.facebook\.net|facebook\.com\/tr/.test(r.url)),
      hasTikTokPixel: requestLog.some(r => /analytics\.tiktok\.com/.test(r.url)),
      hasHotjar: requestLog.some(r => /static\.hotjar\.com/.test(r.url)),
      hasCrazyEgg: requestLog.some(r => /script\.crazyegg\.com/.test(r.url))
    };

    const domBasedDetection = await page.evaluate(() => {
      const scripts = [...document.scripts];

      const hasGA4 = scripts.some(s => /gtag\/js\?id=G-/.test(s.src)) || typeof gtag !== 'undefined';
      const hasUA = scripts.some(s => /google-analytics\.com\/analytics\.js/.test(s.src)) || typeof ga !== 'undefined';
      const hasGTM = scripts.some(s => /googletagmanager\.com\/gtm\.js/.test(s.src)) || !!window.dataLayer;
      const hasGoogleAds = scripts.some(s => /googleadservices\.com|googlesyndication\.com/.test(s.src));
      const hasMetaPixel = typeof fbq !== 'undefined' || scripts.some(s => /connect\.facebook\.net/.test(s.src));
      const hasTikTokPixel = typeof ttq !== 'undefined' || scripts.some(s => /analytics\.tiktok\.com/.test(s.src));
      const hasHotjar = typeof hj !== 'undefined' || scripts.some(s => /static\.hotjar\.com/.test(s.src));
      const hasCrazyEgg = typeof CE !== 'undefined' || scripts.some(s => /script\.crazyegg\.com/.test(s.src));

      const dlEvents = Array.isArray(window.dataLayer)
        ? window.dataLayer.map(e => e.event).filter(Boolean) : [];

      const iframes = [...document.querySelectorAll('iframe')];
      const hasGoogleAdsFrame = iframes.some(iframe => /googleadservices|googlesyndication/.test(iframe.src));
      const hasMetaFrame = iframes.some(iframe => /facebook\.com/.test(iframe.src));

      return {
        hasGA4, hasUA, hasGTM,
        hasGoogleAds: hasGoogleAds || hasGoogleAdsFrame,
        hasMetaPixel: hasMetaPixel || hasMetaFrame,
        hasTikTokPixel, hasHotjar, hasCrazyEgg,
        dlEvents, scriptCount: scripts.length, iframeCount: iframes.length
      };
    });

    return {
      hasGA4: networkBasedDetection.hasGA4 || domBasedDetection.hasGA4,
      hasUA: networkBasedDetection.hasUA || domBasedDetection.hasUA,
      hasGTM: networkBasedDetection.hasGTM || domBasedDetection.hasGTM,
      hasGoogleAds: networkBasedDetection.hasGoogleAds || domBasedDetection.hasGoogleAds,
      hasMetaPixel: networkBasedDetection.hasMetaPixel || domBasedDetection.hasMetaPixel,
      hasTikTokPixel: networkBasedDetection.hasTikTokPixel || domBasedDetection.hasTikTokPixel,
      hasHotjar: networkBasedDetection.hasHotjar || domBasedDetection.hasHotjar,
      hasCrazyEgg: networkBasedDetection.hasCrazyEgg || domBasedDetection.hasCrazyEgg,
      dlEvents: domBasedDetection.dlEvents,
      advanced: {
        networkDetection: networkBasedDetection,
        domDetection: domBasedDetection
      }
    };
  }

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

    if (!noConsent && !withAccept && !withRejectConsent) return { relevant: false };

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
      withAccept,
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
      'googletagmanager': '📊 GTM blockiert - alle Marketing-Tags betroffen',
      'analytics.tiktok.com': '🎵 TikTok Pixel blockiert - TikTok Ads ROI unbekannt',
      'static.hotjar.com': '🖱️ Hotjar blockiert - Nutzerverhalten unbekannt',
      'CORS': '🌐 CORS-Problem - externes Script nicht ladbar',
      'ERR_NAME_NOT_RESOLVED': '🌐 DNS-Problem - Service nicht erreichbar',
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
      return `📱 Meta Pixel (${status}) - Retargeting/ROI betroffen`;
    }
    if (url.includes('analytics') && url.includes('google')) {
      return `📊 Google Analytics (${status}) - Besucherdaten unvollständig`;
    }
    if (url.includes('tiktok')) {
      return `🎵 TikTok Pixel (${status}) - Kampagnen laufen unoptimiert`;
    }
    if (url.includes('hotjar')) {
      return `🖱️ Hotjar (${status}) - Verhalten-Analyse eingeschränkt`;
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
      return 'CSP-Header prüfen und Marketing-Domains in script-src/connect-src whitelisten';
    }
    return 'Entwickler-Konsole öffnen, Fehlerstack analysieren, betroffene Datei fixen';
  }

  suggestFixForUrl(url, error) {
    try {
      const domain = new URL(url).hostname;
      if (error?.includes('CSP') || error?.includes('BLOCKED')) {
        return `CSP-Header erweitern:\nContent-Security-Policy:\n  script-src ... https://${domain};\n  connect-src ... https://${domain};`;
      }
      if (error?.includes('CORS')) {
        return `CORS-Header von ${domain} konfigurieren:\nAccess-Control-Allow-Origin: ${new URL(url).origin}`;
      }
      if (error?.includes('DNS') || error?.includes('NAME_NOT_RESOLVED')) {
        return `DNS-Konfiguration prüfen: nslookup ${domain}`;
      }
      return `Server-Erreichbarkeit prüfen: curl -I https://${domain}`;
    } catch {
      return 'URL-Format prüfen und Konnektivität testen';
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

// ─────────────────────────────────────────────────────────────────────────────
// API
// ─────────────────────────────────────────────────────────────────────────────
app.post('/scan', async (req, res) => {
  const { url } = req.body || {};
  if (!url) {
    console.warn('Scan request missing URL body');
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

// Health
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: VERSION,
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Version
app.get('/version', (_req, res) => {
  res.json({
    version: VERSION,
    buildTime: new Date().toISOString(),
    nodeVersion: process.version
  });
});

// Mini-Diagnose
app.get('/ping', (_req, res) => res.type('text').send('pong'));

// ─────────────────────────────────────────────────────────────────────────────
// UI (simplifiziert, aber hübsch; ruft garantiert die richtige /scan-URL auf)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/', (_req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Ultimate Website Scanner</title>
<style>
  *{box-sizing:border-box} body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial;background:linear-gradient(135deg,#667eea,#764ba2);margin:0;padding:24px;color:#1a202c}
  .container{max-width:1000px;margin:0 auto;background:#fff;border-radius:16px;box-shadow:0 25px 50px rgba(0,0,0,.15);overflow:hidden}
  .header{background:linear-gradient(135deg,#2d3748,#1a202c);color:#fff;padding:40px;text-align:center}
  .header h1{margin:0 0 12px;font-size:2rem}
  .form{padding:32px}
  label{font-weight:600;display:block;margin-bottom:8px}
  input[type=url]{width:100%;padding:16px;border:2px solid #e2e8f0;border-radius:12px;font-size:16px}
  button{margin-top:16px;width:100%;padding:16px;border:0;border-radius:12px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;font-weight:700;font-size:16px;cursor:pointer}
  .loading{display:none;margin:16px 0;padding:16px;background:#f7fafc;border-radius:10px;color:#4a5568}
  .results{display:none;padding:0 32px 32px}
  .risk{padding:16px;border-radius:12px;margin-bottom:16px;font-weight:600;text-align:center}
  .risk.high{background:#fed7d7;color:#c53030;border:2px solid #fc8181}
  .risk.medium{background:#fefcbf;color:#d69e2e;border:2px solid #f6e05e}
  .risk.low{background:#c6f6d5;color:#2f855a;border:2px solid #68d391}
  .section{border:1px solid #e2e8f0;border-radius:12px;margin:16px 0;overflow:hidden}
  .section .head{background:#f8f9fa;padding:14px 18px;font-weight:600}
  .section .body{padding:18px}
  .issue{background:#fff5f5;border:1px solid #feb2b2;border-radius:10px;padding:12px;margin:12px 0}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:.9em}
  small{color:#718096}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔍 Website-Scanner: DSGVO & Marketing Check</h1>
      <p>3 Sessions: ohne Consent • mit Accept • mit Reject</p>
    </div>
    <div class="form">
      <label for="url">Website-URL:</label>
      <input id="url" type="url" placeholder="https://example.com" required />
      <button id="start">🔍 Vollständigen Scan starten</button>
      <div id="loading" class="loading">⏳ Läuft… bitte geduldig sein (60–90s)</div>
    </div>
    <div id="results" class="results"></div>
    <div class="form" style="border-top:1px solid #edf2f7">
      <small>Version ${VERSION} • Powered by Playwright</small>
    </div>
  </div>

<script>
const $ = sel => document.querySelector(sel);
$('#start').addEventListener('click', async () => {
  const url = $('#url').value.trim();
  if (!url) { alert('Bitte eine URL eingeben (https://…)'); return; }

  const loading = $('#loading');
  const results = $('#results');
  loading.style.display = 'block';
  results.style.display = 'none';

  try {
    const resp = await fetch(\`\${location.origin}/scan\`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await resp.json();
    loading.style.display = 'none';

    if (!resp.ok) {
      results.innerHTML = \`
        <div class="section">
          <div class="head">❌ Scan fehlgeschlagen</div>
          <div class="body">
            <p><strong>Fehler:</strong> \${data.error}</p>
            <p class="mono">\${data.details || ''}</p>
          </div>
        </div>\`;
      results.style.display = 'block';
      return;
    }

    const marketingTags = data.summary.marketingTags || [];
    const high = data.summary.highPriorityIssues || 0;
    const risk = high >= 3 || marketingTags.filter(t=>t.compliance==='bad').length >= 2
      ? 'high' : (high>=1 ? 'medium' : 'low');

    results.innerHTML = \`
      <div class="risk \${risk}">
        \${risk==='high'?'🚨 Hohes Risiko':risk==='medium'?'⚠️ Mittleres Risiko':'✅ Niedriges Risiko'}
        <div><small>\${data.scannedUrl} • \${data.summary.totalIssues} Issues</small></div>
        <div><small>Gescannt am: \${data.timestamp}</small></div>
      </div>

      <div class="section">
        <div class="head">🍪 Consent-Compliance</div>
        <div class="body">
          \${marketingTags.length
            ? marketingTags.map(tag => \`
                <div class="issue">
                  <strong>\${tag.name}</strong>: \${tag.impact}<br/>
                  <span class="mono">Ohne: \${tag.withoutConsent?'Lädt ❌':'Blockiert ✅'} | Accept: \${tag.withAccept?'Lädt ✅':'Blockiert ❌'} | Reject: \${tag.withReject?'Lädt ❌':'Blockiert ✅'}</span>
                </div>\`).join('')
            : '<p>Keine Marketing-Tags erkannt.</p>'}
        </div>
      </div>

      \${data.details.errors.length ? \`
        <div class="section">
          <div class="head">⚠️ JavaScript & Console Errors (\${data.details.errors.length})</div>
          <div class="body">
            \${data.details.errors.slice(0,10).map(e => \`
              <div class="issue">
                <div><strong>Business-Impact:</strong> \${e.translation}</div>
                <div class="mono">\${e.message}</div>
                <div class="mono"><em>Fix:</em> \${e.techFix}</div>
              </div>\`).join('')}
            \${data.details.errors.length>10?'<small>…und weitere</small>':''}
          </div>
        </div>\` : ''}

      \${data.details.cspViolations.length ? \`
        <div class="section">
          <div class="head">🔒 CSP-Violations (\${data.details.cspViolations.length})</div>
          <div class="body">
            \${data.details.cspViolations.map(v => \`
              <div class="issue">
                <div><strong>Impact:</strong> \${v.translation}</div>
                <div class="mono">\${v.message}</div>
                <div class="mono"><em>CSP-Fix:</em> \${v.techFix}</div>
              </div>\`).join('')}
          </div>
        </div>\` : ''}

      \${data.details.networkIssues.length ? \`
        <div class="section">
          <div class="head">🌐 Netzwerk-Issues (\${data.details.networkIssues.length})</div>
          <div class="body">
            \${data.details.networkIssues.slice(0,10).map(n => \`
              <div class="issue">
                <div><strong>Impact:</strong> \${n.translation}</div>
                <div class="mono">\${n.url} — \${n.status}</div>
                <div class="mono"><em>Fix:</em> \${n.techFix}</div>
              </div>\`).join('')}
            \${data.details.networkIssues.length>10?'<small>…und weitere</small>':''}
          </div>
        </div>\` : ''}
    \`;
    results.style.display = 'block';

  } catch (err) {
    loading.style.display = 'none';
    results.innerHTML = \`
      <div class="section">
        <div class="head">❌ Scan fehlgeschlagen (Client)</div>
        <div class="body"><div class="mono">\${err?.message || err}</div></div>
      </div>\`;
    results.style.display = 'block';
  }
});
</script>
</body>
</html>
  `);
});

// ─────────────────────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Website Scanner running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔍 Scanner UI: http://localhost:${PORT}/`);
});
