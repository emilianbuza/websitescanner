import express from 'express';
import { chromium } from 'playwright';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import fs from 'fs/promises';

const app = express();
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
    page.on('requestfinished', request => {
      scanData.requestLog.push({
        url: request.url(),
        method: request.method(),
        resourceType: request.resourceType(),
        status: request.response()?.status() || 0
      });
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
          translation: this.translateNetworkIssue(response.url(), response.status().toString()),
          techFix: this.suggestFixForUrl(response.url(), response.status().toString()),
          consentMode
        });
      }
    });

    try {
      // Navigate with enhanced stability
      await page.goto(url, { 
        waitUntil: 'networkidle',
        timeout: 60000 
      });

      // Handle consent based on mode
      if (consentMode === 'accept') {
        await this.handleConsent(page, 'accept');
      } else if (consentMode === 'reject') {
        await this.handleConsent(page, 'reject');
      }

      // Enhanced loading with lazy-load trigger
      await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
      await page.waitForTimeout(3000); // Allow marketing tags to load

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
      summary: {
        totalIssues,
        highPriorityIssues,
        marketingTags: this.marketingTags,
        consentCompliance: this.results
      },
      details: {
        errors: allErrors,
        networkIssues: allNetworkIssues,
        cspViolations: allCSPViolations
      }
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
    const results = await scanner.scanWithRetry(url);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: VERSION });
});

app.listen(PORT, () => {
  console.log(`🚀 Website Scanner running on port ${PORT}`);
});
