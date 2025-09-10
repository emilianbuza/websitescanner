import express from 'express';
import { chromium } from 'playwright';
import rateLimit from 'express-rate-limit';
import cors from 'cors';

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const VERSION = process.env.GIT_SHA || '2.1.0';

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

  validateUrl(url) {
    try {
      const u = new URL(url);
      
      if (!/^https?:$/.test(u.protocol)) {
        throw new Error('Only HTTP/HTTPS URLs allowed');
      }
      
      const hostname = u.hostname.toLowerCase();
      
      if (/(^|\.)(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)/.test(hostname)) {
        throw new Error('Private/internal IPs not allowed');
      }
      
      if (/^\[?::1\]?$/.test(hostname)) {
        throw new Error('Loopback IPv6 not allowed');
      }
      
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
      console.log('🚫 Run A: Scanning without consent...');
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
      window.__requestLog = [];
      
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
          location: msg.location(),
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
      await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: 20000
      });

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
        domain: domain
      },
      {
        name: 'cookielawinfo-checkbox-necessary',
        value: 'yes',
        domain: domain
      },
      {
        name: 'cookielawinfo-checkbox-analytics',
        value: acceptAll ? 'yes' : 'no',
        domain: domain
      },
      {
        name: 'cookielawinfo-checkbox-advertisement',
        value: acceptAll ? 'yes' : 'no',
        domain: domain
      }
    ];

    for (const cookie of consentCookies) {
      try {
        await context.addCookies([cookie]);
      } catch (error) {
        // Cookie setting can fail, that's ok
      }
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

      const dlEvents = Array.isArray(window.dataLayer) ? 
                       window.dataLayer.map(e => e.event).filter(Boolean) : [];

      const iframes = [...document.querySelectorAll('iframe')];
      const hasGoogleAdsFrame = iframes.some(iframe => /googleadservices|googlesyndication/.test(iframe.src));
      const hasMetaFrame = iframes.some(iframe => /facebook\.com/.test(iframe.src));

      return {
        hasGA4: hasGA4,
        hasUA: hasUA,
        hasGTM: hasGTM,
        hasGoogleAds: hasGoogleAds || hasGoogleAdsFrame,
        hasMetaPixel: hasMetaPixel || hasMetaFrame,
        hasTikTokPixel: hasTikTokPixel,
        hasHotjar: hasHotjar,
        hasCrazyEgg: hasCrazyEgg,
        dlEvents,
        scriptCount: scripts.length,
        iframeCount: iframes.length
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
      'googleadservices': '🎯 Google Ads Conversion-Tracking blockiert - ROI nicht messbar, Budget-Optimierung unmöglich',
      'connect.facebook.net': '📱 Meta Pixel blockiert - Facebook/Instagram Ads Performance unbekannt',
      'googletagmanager': '📊 Google Tag Manager blockiert - alle Marketing-Tags betroffen',
      'analytics.tiktok.com': '🎵 TikTok Pixel blockiert - TikTok Ads ROI unbekannt',
      'static.hotjar.com': '🖱️ Hotjar Heatmap-Tracking blockiert - Nutzerverhalten unbekannt',
      'CORS': '🌐 Cross-Origin Problem - externes Marketing-Script nicht ladbar',
      'ERR_NAME_NOT_RESOLVED': '🌐 DNS-Problem - Marketing-Service nicht erreichbar',
      'ERR_INTERNET_DISCONNECTED': '📡 Internetverbindung unterbrochen'
    };

    for (let [key, translation] of Object.entries(translations)) {
      if (errorMessage.includes(key)) {
        return translation;
      }
    }
    
    return '⚠️ Technischer Fehler gefunden - kann Marketing-Performance beeinträchtigen';
  }

  translateNetworkIssue(url, status) {
    if (url.includes('googleadservices') || url.includes('googlesyndication')) {
      return `🎯 Google Ads (${status}) - Conversion-Tracking gestört, Budget-Verschwendung wahrscheinlich`;
    }
    if (url.includes('facebook.net') || url.includes('meta')) {
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
    if (errorMessage.includes('static.hotjar.com')) {
      return `CSP erweitern:\nContent-Security-Policy:\n  script-src ... https://static.hotjar.com;\n  connect-src ... https://static.hotjar.com;`;
    }
    if (errorMessage.includes('Content Security Policy')) {
      return 'CSP-Header überprüfen und alle Marketing-Domains in script-src und connect-src whitelisten';
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
    
    // Form submission
    document.getElementById('scanForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = document.getElementById('url').value;
      const loading = document.getElementById('loading');
      const results = document.getElementById('results');
      const scanBtn = document.getElementById('scanBtn');
      const progressFill = document.getElementById('progressFill');
      const loadingText = document.getElementById('loadingText');
      
      // Reset + UI updates
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning läuft...';
      loading.style.display = 'block';
      results.style.display = 'none';
      progressFill.style.width = '0%';
      
      try {
        const response = await fetch('/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
        
        const data = await response.json();
        if (response.ok) {
          displayResults(data);
        } else {
          throw new Error(data.error || data.details);
        }
      } catch (error) {
        results.innerHTML = `
          <div class="section">
            <div class="section-content">
              <h3 style="color: #e53e3e;">❌ Scan fehlgeschlagen</h3>
              <p><strong>Fehler:</strong> ${error.message}</p>
              <div class="tech-details">
                <strong>Mögliche Ursachen:</strong><br>
                • Website nicht erreichbar oder blockiert Scanner<br>
                • Timeout nach 60+ Sekunden<br>
                • Temporäre Netzwerkprobleme<br>
                • Website verwendet aggressive Bot-Protection
              </div>
            </div>
          </div>
        `;
        results.style.display = 'block';
      }
      
      // Reset Button
      loading.style.display = 'none';
      scanBtn.disabled = false;
      scanBtn.textContent = '🔍 Vollständigen 3-Session-Scan starten';
    });
    
    // ======================
    // RENDER-FUNKTIONEN
    // ======================
    function displayResults(data) {
      const results = document.getElementById('results');
      const marketingTags = data.summary.marketingTags || [];
      
      results.innerHTML = `
        <div class="export-buttons">
          <button class="export-btn" onclick="exportToPDF()">📄 PDF Export</button>
          <button class="export-btn" onclick="copyResults()">📋 Ergebnisse kopieren</button>
          <button class="export-btn" onclick="shareResults()">🔗 Link teilen</button>
        </div>
        
        <div class="risk-indicator risk-high">
          <h3>🚨 Scan abgeschlossen</h3>
          <p><strong>${data.scannedUrl}</strong></p>
          <p>${data.summary.totalIssues} Issues gefunden • ${marketingTags.length} Marketing-Tags analysiert</p>
        </div>
        
        ${renderErrors(data.details.errors)}
        ${renderNetworkIssues(data.details.networkIssues)}
        ${renderCSPViolations(data.details.cspViolations)}
      `;
      results.style.display = 'block';
    }

    function renderErrors(errors = []) {
      if (!errors.length) return '';
      return `
        <div class="section">
          <div class="section-header" onclick="toggleSection(this)">
            ⚠️ JavaScript & Console Errors
            <span class="badge high">${errors.length} ▼</span>
          </div>
          <div class="section-content">
            ${errors.slice(0, 10).map(error => `
              <div class="issue-card risk-${error.priority}">
                <h3>🚨 Problem: ${simplifyProblem(error)}</h3>
                <p><strong>Was bedeutet das?</strong><br>${error.translation}</p>
                <p><strong>Warum passiert das?</strong><br>${explainCause(error)}</p>
                <div class="solution-box">
                  <strong>💡 Lösung für Entwickler:</strong>
                  <pre>${error.techFix}</pre>
                  <button class="copy-button" onclick="copyToClipboard('${error.techFix}')">📋 Kopieren</button>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    function renderNetworkIssues(issues = []) {
      if (!issues.length) return '';
      return `
        <div class="section">
          <div class="section-header" onclick="toggleSection(this)">
            🌐 Netzwerk & Loading Issues
            <span class="badge medium">${issues.length} ▼</span>
          </div>
          <div class="section-content">
            ${issues.map(issue => `
              <div class="issue-card risk-${issue.priority}">
                <h3>🚨 Problem: ${simplifyNetworkProblem(issue)}</h3>
                <p><strong>Was bedeutet das?</strong><br>${issue.translation}</p>
                <p><strong>Warum passiert das?</strong><br>${explainNetworkCause(issue)}</p>
                <div class="solution-box">
                  <strong>💡 Lösung für Entwickler:</strong>
                  <pre>${issue.techFix}</pre>
                  <button class="copy-button" onclick="copyToClipboard('${issue.techFix}')">📋 Kopieren</button>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    function renderCSPViolations(violations = []) {
      if (!violations.length) return '';
      return `
        <div class="section">
          <div class="section-header" onclick="toggleSection(this)">
            🔒 CSP-Violations
            <span class="badge critical">${violations.length} ▼</span>
          </div>
          <div class="section-content">
            ${violations.map(v => `
              <div class="issue-card risk-high">
                <h3>🚨 Problem: Sicherheitsrichtlinie blockiert Skript</h3>
                <p><strong>Was bedeutet das?</strong><br>${v.translation}</p>
                <p><strong>Warum passiert das?</strong><br><code>${v.message}</code></p>
                <div class="solution-box">
                  <strong>💡 Lösung für Entwickler:</strong>
                  <pre>${v.techFix}</pre>
                  <button class="copy-button" onclick="copyToClipboard('${v.techFix}')">📋 Kopieren</button>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    // ======================
    // HILFSFUNKTIONEN
    // ======================
    function simplifyProblem(error) {
      if (error.message.includes("facebook")) return "Facebook Pixel blockiert";
      if (error.message.includes("google")) return "Google Analytics / Ads blockiert";
      if (error.message.includes("CSP")) return "Sicherheitsrichtlinie blockiert Marketing-Skript";
      if (error.message.includes("DNS")) return "Website-Adresse nicht erreichbar";
      return "Allgemeiner Website-Fehler";
    }

    function explainCause(error) {
      if (error.type === "CSP Violation") return "Sicherheits-Einstellungen (CSP) blockieren Marketing-Skripte.";
      if (error.type === "Uncaught Error") return "Ein JavaScript-Fehler bricht Teile der Seite ab.";
      if (error.type === "Network Issue") return "Ein externer Dienst konnte nicht geladen werden.";
      return "Die genaue Ursache muss dein Entwickler prüfen.";
    }

    function simplifyNetworkProblem(issue) {
      if (issue.url.includes("facebook")) return "Meta Pixel nicht erreichbar";
      if (issue.url.includes("google")) return "Google Analytics / Ads Verbindung fehlgeschlagen";
      if (issue.url.includes("tiktok")) return "TikTok Pixel konnte nicht laden";
      if (issue.url.includes("hotjar")) return "Hotjar Heatmap blockiert";
      return "Netzwerkproblem mit externer Ressource";
    }

    function explainNetworkCause(issue) {
      if (String(issue.status).includes("DNS")) return "Domain konnte nicht aufgelöst werden (DNS-Fehler).";
      if (String(issue.status).includes("CSP")) return "CSP blockiert diese Ressource.";
      if (String(issue.status).startsWith("4")) return "Ressource nicht gefunden (Client-Fehler).";
      if (String(issue.status).startsWith("5")) return "Server des Drittanbieters antwortet nicht (Server-Fehler).";
      return "Ressource konnte nicht geladen werden (Blocker, CSP oder Timeout).";
    }

    // Copy / PDF / Share etc.
    function toggleSection(header) { const c = header.nextElementSibling; c.style.display = c.style.display === 'none' ? 'block' : 'none'; }
    function copyToClipboard(text) { navigator.clipboard.writeText(text); }
    function exportToPDF() { window.print(); }
    function copyResults() { navigator.clipboard.writeText(document.getElementById('results').innerText); }
    function shareResults() { navigator.clipboard.writeText(window.location.href); }
  </script>

</body>
</html>
  `);
});

app.listen(PORT, () => {
  console.log(`🚀 Website Scanner running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔍 Scanner UI: http://localhost:${PORT}/`);
});






