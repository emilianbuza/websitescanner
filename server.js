import express from 'express';
import { chromium } from 'playwright';
import rateLimit from 'express-rate-limit';
import cors from 'cors';

const app = express();
app.set('trust proxy', 1); // Render/Heroku/Proxy vor App

const PORT = process.env.PORT || 3000;
const VERSION = process.env.GIT_SHA || '2.0.0';

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

  // Enhanced URL validation with IPv6 and obfuscation protection
  validateUrl(url) {
    try {
      const u = new URL(url);
      
      if (!/^https?:$/.test(u.protocol)) {
        throw new Error('Only HTTP/HTTPS URLs allowed');
      }
      
      const hostname = u.hostname.toLowerCase();
      
      // Block private networks (IPv4)
      if (/(^|\.)(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)/.test(hostname)) {
        throw new Error('Private/internal IPs not allowed');
      }
      
      // Block IPv6 loopback
      if (/^\[?::1\]?$/.test(hostname)) {
        throw new Error('Loopback IPv6 not allowed');
      }
      
      // Block dot-decimal IP obfuscation
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
      // Run A: Without Consent (clean session)
      console.log('🚫 Run A: Scanning without consent...');
      this.results.withoutConsent = await this.runSingleScan(browser, url, 'no-consent');
      
      // Run B: With Consent Accepted (fresh session)
      console.log('✅ Run B: Scanning with consent accepted...');
      this.results.withConsent = await this.runSingleScan(browser, url, 'accept');
      
      // Run C: With Consent Rejected (fresh session)
      console.log('❌ Run C: Scanning with consent rejected...');
      this.results.withReject = await this.runSingleScan(browser, url, 'reject');
      
      // Compare results and generate insights
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

    // Set deterministic consent state via cookies if needed
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

    // Enhanced CSP violation tracking (isolated per run)
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

    // Console errors with enhanced classification
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

    // Page errors (uncaught exceptions)
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

    // Enhanced network monitoring
    page.on('requestfinished', async request => {
  try {
    const response = await request.response(); // PW 1.46: async!
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
    // Fallback, falls etwas im Handler schiefgeht
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
  // 1) Laden bis DOM bereit ist (keine langen networkidle-Wartezeiten)
  await page.goto(url, {
    waitUntil: 'domcontentloaded',
    timeout: 20000
  });

  // 2) Consent je nach Modus klicken (damit danach die richtigen Tags laden)
  if (consentMode === 'accept') {
    await this.handleConsent(page, 'accept');
  } else if (consentMode === 'reject') {
    await this.handleConsent(page, 'reject');
  }

  // 3) Kurze, deterministische Nachladephase für Tags
  await page.evaluate(() => { window.scrollTo(0, document.body.scrollHeight); });
  await Promise.race([
    page.waitForLoadState('networkidle', { timeout: 3000 }).catch(() => {}),
    page.waitForTimeout(1500)
  ]);



      // Robust marketing tag detection
      scanData.marketingTags = await this.checkMarketingTagsDeep(page, scanData.requestLog);
      
      // Collect CSP violations for this specific run
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

  // Set consent cookies for deterministic testing
  async setConsentCookies(context, url, acceptAll) {
    const domain = new URL(url).hostname;
    
    // Common CMP cookie patterns
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
      // Wait for potential consent banner
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

  // Deep marketing tag detection with network analysis
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
      // Script tag detection
      const scripts = [...document.scripts];
      
      const hasGA4 = scripts.some(s => /gtag\/js\?id=G-/.test(s.src)) || typeof gtag !== 'undefined';
      const hasUA = scripts.some(s => /google-analytics\.com\/analytics\.js/.test(s.src)) || typeof ga !== 'undefined';
      const hasGTM = scripts.some(s => /googletagmanager\.com\/gtm\.js/.test(s.src)) || !!window.dataLayer;
      const hasGoogleAds = scripts.some(s => /googleadservices\.com|googlesyndication\.com/.test(s.src));
      const hasMetaPixel = typeof fbq !== 'undefined' || scripts.some(s => /connect\.facebook\.net/.test(s.src));
      const hasTikTokPixel = typeof ttq !== 'undefined' || scripts.some(s => /analytics\.tiktok\.com/.test(s.src));
      const hasHotjar = typeof hj !== 'undefined' || scripts.some(s => /static\.hotjar\.com/.test(s.src));
      const hasCrazyEgg = typeof CE !== 'undefined' || scripts.some(s => /script\.crazyegg\.com/.test(s.src));

      // DataLayer events
      const dlEvents = Array.isArray(window.dataLayer) ? 
                       window.dataLayer.map(e => e.event).filter(Boolean) : [];

      // Check iframes for embedded tracking
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

    // Combine network and DOM detection for maximum accuracy
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

    // Skip if tag not found in any scenario
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

  // Enhanced error classification
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

  // Enhanced error translation
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

  // Enhanced fix suggestions with copy-paste ready snippets
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

// Frontend Route - Das komplette UI
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultimate Website Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6; color: #333; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; padding: 20px;
        }
        .container { 
            max-width: 1000px; margin: 0 auto; background: white;
            border-radius: 16px; box-shadow: 0 25px 50px rgba(0,0,0,0.15);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            color: white; padding: 40px; text-align: center; 
        }
        .header h1 { font-size: 3em; margin-bottom: 15px; font-weight: 700; }
        .header p { opacity: 0.9; font-size: 1.2em; margin-bottom: 10px; }
        .features { 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px; padding: 20px; background: rgba(255,255,255,0.1);
        }
        .feature { text-align: center; padding: 15px; }
        .feature-icon { font-size: 2em; margin-bottom: 10px; }
        .form-section { padding: 50px; }
        .input-group { margin-bottom: 30px; }
        label { 
            display: block; margin-bottom: 10px; font-weight: 600; 
            color: #2d3748; font-size: 1.1em;
        }
        input[type="url"] { 
            width: 100%; padding: 18px; border: 2px solid #e2e8f0; 
            border-radius: 12px; font-size: 16px; transition: all 0.3s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        input[type="url"]:focus { 
            border-color: #667eea; outline: none; 
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .scan-button { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 20px 40px; border-radius: 12px; 
            font-size: 18px; font-weight: 600; cursor: pointer; width: 100%;
            transition: all 0.3s; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        .scan-button:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6);
        }
        .scan-button:disabled { 
            opacity: 0.6; cursor: not-allowed; transform: none;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.2);
        }
        .loading { 
            display: none; text-align: center; padding: 30px; color: #667eea;
            background: #f8f9fa; margin: 20px; border-radius: 12px;
        }
        .progress-bar {
            width: 100%; height: 6px; background: #e2e8f0; border-radius: 3px;
            margin: 20px 0; overflow: hidden;
        }
        .progress-fill {
            height: 100%; background: linear-gradient(90deg, #667eea, #764ba2);
            width: 0%; transition: width 0.5s; border-radius: 3px;
        }
        .results { display: none; padding: 0 50px 50px; }
        .risk-indicator {
            padding: 20px; border-radius: 12px; margin-bottom: 25px; 
            font-weight: 600; text-align: center;
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
        }
        .section-header { 
            background: linear-gradient(135deg, #f8f9fa 0%, #e2e8f0 100%);
            padding: 20px; font-weight: 600; display: flex;
            justify-content: space-between; align-items: center; font-size: 1.1em;
        }
        .badge { 
            background: #4299e1; color: white; padding: 6px 12px; 
            border-radius: 15px; font-size: 0.85em; font-weight: 500;
        }
        .badge.high { background: #e53e3e; }
        .badge.medium { background: #d69e2e; }
        .section-content { padding: 25px; }
        .compliance-item { 
            padding: 18px; margin: 15px 0; border-radius: 10px; 
            border-left: 5px solid; position: relative;
        }
        .compliance-perfect { background: #f0fff4; border-left-color: #38a169; }
        .compliance-good { background: #fefcbf; border-left-color: #d69e2e; }
        .compliance-bad { background: #fff5f5; border-left-color: #e53e3e; }
        .compliance-missing { background: #f7fafc; border-left-color: #a0aec0; }
        .compliance-inconsistent { background: #fdf2e9; border-left-color: #ed8936; }
        .consent-matrix {
            display: grid; grid-template-columns: 1fr 1fr 1fr;
            gap: 10px; margin-top: 15px; font-size: 0.9em;
            background: #f8f9fa; padding: 12px; border-radius: 8px;
        }
        .consent-result { 
            text-align: center; padding: 8px; border-radius: 6px; 
            font-weight: 500;
        }
        .consent-pass { background: #c6f6d5; color: #2f855a; }
        .consent-fail { background: #fed7d7; color: #c53030; }
        .issue-item { 
            background: #fff5f5; border: 1px solid #feb2b2; 
            border-radius: 10px; padding: 20px; margin: 15px 0; 
        }
        .tech-details { 
            background: #f7fafc; padding: 15px; border-radius: 8px; 
            margin-top: 12px; font-size: 0.95em; color: #4a5568; 
            font-family: 'Monaco', 'Menlo', monospace;
        }
        .fix-suggestion {
            background: #e6fffa; border: 1px solid #4fd1c7;
            padding: 12px; border-radius: 8px; margin-top: 10px;
            font-family: 'Monaco', 'Menlo', monospace; font-size: 0.9em;
        }
        .priority-critical { border-left: 5px solid #c53030; }
        .priority-high { border-left: 5px solid #e53e3e; }
        .priority-medium { border-left: 5px solid #d69e2e; }
        .priority-low { border-left: 5px solid #4299e1; }
        .footer {
            text-align: center; padding: 30px; background: #f8f9fa;
            color: #718096; font-size: 0.9em;
        }
    </style>
</head>
<body>
  <div class="container">
<div class="header" style="text-align:center; padding:60px 20px; background:#123456; color:#fff;">
  <h1 style="font-size:2.2em; font-weight:700; margin-bottom:20px; line-height:1.3;">
    🔍 Finde sofort heraus, ob deine Website wirklich funktioniert – auch wenn du kein Programmierer bist
  </h1>
  <p style="font-size:1.1em; max-width:800px; margin:0 auto 15px;">
    Unser Scanner prüft deine Website in Sekunden und zeigt dir:
  </p>
  <ul style="text-align:left; display:inline-block; font-size:1em; line-height:1.6; margin:0 auto 20px; padding-left:20px; max-width:600px; color:#fff;">
    <li>ob dein Cookie-Banner rechtssicher arbeitet,</li>
    <li>ob Google Analytics, Google Ads & Co. korrekt laufen,</li>
    <li>welche Fehler dein Tracking blockieren – und wie du sie beheben kannst.</li>
  </ul>
  <p style="font-size:1em; max-width:800px; margin:0 auto 30px;">
    So erkennst du sofort, wo Budget und Daten verloren gehen – klar erklärt, ohne Fachchinesisch.
  </p>

  <!-- Features direkt hier -->
  <div class="features" style="margin-top:40px;">
    <div class="feature">
      <div class="feature-icon">🍪</div>
      <h3>Cookie-Banner-Test</h3>
      <p>Prüft, ob dein Cookie-Banner wirklich funktioniert: Was passiert ohne Zustimmung, mit Zustimmung und wenn man ablehnt?</p>
    </div>
    <div class="feature">
      <div class="feature-icon">🔒</div>
      <h3>Sicherheits-Check (CSP)</h3>
      <p>Findet heraus, ob deine Sicherheitseinstellungen wichtige Marketing-Skripte blockieren – z. B. Google Analytics oder Ads.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">📊</div>
      <h3>DSGVO-Konformität</h3>
      <p>Zeigt dir, ob Google Analytics, Google Ads, Meta Pixel & Co. korrekt laufen oder blockiert werden.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">💰</div>
      <h3>Marketing-Performance</h3>
      <p>Verständlich erklärt: Welche Fehler kosten dich Daten, Reichweite und Umsatz – und wie du sie beheben kannst.</p>
    </div>
  </div>
</div> <!-- /header -->
        <div class="form-section">
            <form id="scanForm">
                <div class="input-group">
                    <label for="url">Website-URL für vollständige Analyse:</label>
                    <input 
                        type="url" 
                        id="url" 
                        placeholder="https://ihre-website.de" 
                        required
                    >
                </div>
                <button type="submit" class="scan-button" id="scanBtn">
                    🔍 Vollständigen Scan starten (3 Sessions)
                </button>
            </form>
            
            <div class="loading" id="loading">
                <h3>⏳ Führe umfassende Analyse durch...</h3>
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill"></div>
                </div>
                <p id="loadingText">Session 1/3: Ohne Consent...</p>
                <p><small>Das kann 60-90 Sekunden dauern</small></p>
            </div>
        </div>

        <div class="results" id="results"></div>
        
        <div class="footer">
            <p>Powered by Playwright • Version ${VERSION}</p>
        </div>
    </div>

    <script>
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
            
            // Simulate progress
            const progressSteps = [
                { progress: 20, text: 'Session 1/3: Ohne Consent...' },
                { progress: 50, text: 'Session 2/3: Mit Consent akzeptiert...' },
                { progress: 80, text: 'Session 3/3: Mit Consent abgelehnt...' },
                { progress: 100, text: 'Analysiere Ergebnisse...' }
            ];
            
            let stepIndex = 0;
            const progressInterval = setInterval(() => {
                if (stepIndex < progressSteps.length) {
                    const step = progressSteps[stepIndex];
                    progressFill.style.width = step.progress + '%';
                    loadingText.textContent = step.text;
                    stepIndex++;
                }
            }, 15000);
            
            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                
                const data = await response.json();
                
                clearInterval(progressInterval);
                progressFill.style.width = '100%';
                
                if (response.ok) {
                    displayResults(data);
                } else {
                    throw new Error(data.error || data.details);
                }
                
            } catch (error) {
                clearInterval(progressInterval);
                results.innerHTML = \`
                    <div class="section">
                        <div class="section-content">
                            <h3 style="color: #e53e3e;">❌ Scan fehlgeschlagen</h3>
                            <p>\${error.message}</p>
                            <div class="tech-details">
                                Mögliche Ursachen: Website nicht erreichbar, Timeout, 
                                oder temporäre Netzwerkprobleme
                            </div>
                        </div>
                    </div>
                \`;
                results.style.display = 'block';
            }
            
            // UI Reset
            loading.style.display = 'none';
            scanBtn.disabled = false;
            scanBtn.textContent = '🔍 Vollständigen Scan starten (3 Sessions)';
        });
        
        function displayResults(data) {
            const results = document.getElementById('results');
            const marketingTags = data.summary.marketingTags || [];
            const riskLevel = calculateOverallRisk(data);
            
            results.innerHTML = \`
                <div class="risk-indicator risk-\${riskLevel.level}">
                    <h3>\${riskLevel.icon} \${riskLevel.text}</h3>
                    <p>\${data.scannedUrl} • \${data.summary.totalIssues} Issues • \${marketingTags.length} Marketing-Tags analysiert</p>
                    <small>Gescannt am: \${data.timestamp}</small>
                </div>
                
                <div class="section">
                    <div class="section-header">
                        🍪 Consent-Compliance-Matrix
                        <span class="badge">3-Wege-Test</span>
                    </div>
                    <div class="section-content">
                        \${marketingTags.map(tag => \`
                            <div class="compliance-item compliance-\${tag.compliance}">
                                <strong>\${tag.name}:</strong> \${tag.impact}
                                <div class="consent-matrix">
                                    <div class="consent-result \${tag.withoutConsent ? 'consent-fail' : 'consent-pass'}">
                                        Ohne Consent: \${tag.withoutConsent ? '❌ Lädt' : '✅ Blockiert'}
                                    </div>
                                    <div class="consent-result \${tag.withAccept ? 'consent-pass' : 'consent-fail'}">
                                        Mit Accept: \${tag.withAccept ? '✅ Lädt' : '❌ Blockiert'}
                                    </div>
                                    <div class="consent-result \${tag.withReject ? 'consent-fail' : 'consent-pass'}">
                                        Mit Reject: \${tag.withReject ? '❌ Lädt' : '✅ Blockiert'}
                                    </div>
                                </div>
                                <div style="margin-top: 10px;">
                                    <strong>Business-Impact:</strong> \${tag.businessImpact}
                                    <br><strong>DSGVO-Risiko:</strong> \${getGDPRRiskText(tag.gdprRisk)}
                                </div>
                            </div>
                        \`).join('')}
                    </div>
                </div>
                
                \${data.details.errors.length > 0 ? \`
                <div class="section">
                    <div class="section-header">
                        ⚠️ Technische Probleme
                        <span class="badge high">\${data.details.errors.length}</span>
                    </div>
                    <div class="section-content">
                        \${data.details.errors.map(error => \`
                            <div class="issue-item priority-\${error.priority}">
                                <strong>Business-Impact:</strong> \${error.translation}
                                <div class="tech-details">
                                    <strong>Technisch:</strong> \${error.message}
                                    <br><strong>Session:</strong> \${error.consentMode}
                                </div>
                                <div class="fix-suggestion">
                                    <strong>Fix:</strong> \${error.techFix}
                                </div>
                            </div>
                        \`).join('')}
                    </div>
                </div>
                \` : ''}
                
                \${data.details.cspViolations.length > 0 ? \`
                <div class="section">
                    <div class="section-header">
                        🔒 CSP-Violations (Sicherheitsrichtlinien)
                        <span class="badge high">\${data.details.cspViolations.length}</span>
                    </div>
                    <div class="section-content">
                        \${data.details.cspViolations.map(violation => \`
                            <div class="issue-item priority-high">
                                <strong>Business-Impact:</strong> \${violation.translation}
                                <div class="tech-details">
                                    <strong>Violation:</strong> \${violation.message}
                                    <br><strong>Session:</strong> \${violation.consentMode}
                                </div>
                                <div class="fix-suggestion">
                                    <strong>CSP-Fix:</strong> \${violation.techFix}
                                </div>
                            </div>
                        \`).join('')}
                    </div>
                </div>
                \` : ''}
                
                <div class="section">
                    <div class="section-header">💡 Empfohlene Maßnahmen</div>
                    <div class="section-content">
                        <p><strong>1. Sofortige Maßnahmen:</strong> CSP-Violations beheben (höchste Priorität)</p>
                        <p><strong>2. DSGVO-Compliance:</strong> Tags mit "bad" Compliance prüfen</p>
                        <p><strong>3. Business-Impact:</strong> Fehlende Marketing-Tags implementieren</p>
                        <p><strong>4. Monitoring:</strong> Wöchentliche Scans einrichten</p>
                        <br>
                        <p><strong>💬 Support:</strong> Screenshots dieses Reports für Entwickler/Agentur verwenden</p>
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
            
            if (highPriorityIssues >= 3 || badCompliance >= 2) {
                return { level: 'high', icon: '🚨', text: 'Hohes Risiko - Sofortiger Handlungsbedarf' };
            } else if (highPriorityIssues >= 1 || badCompliance >= 1 || missingTags >= 2) {
                return { level: 'medium', icon: '⚠️', text: 'Mittleres Risiko - Optimierung empfohlen' };
            } else {
                return { level: 'low', icon: '✅', text: 'Niedriges Risiko - Setup ist solide' };
            }
        }
        
        function getGDPRRiskText(risk) {
            const risks = {
                'none': '✅ Kein Risiko',
                'low': '🟡 Geringes Risiko',
                'medium': '🟠 Mittleres Risiko',
                'high': '🔴 Hohes Abmahnrisiko'
            };
            return risks[risk] || '🤔 Unbekannt';
        }
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





