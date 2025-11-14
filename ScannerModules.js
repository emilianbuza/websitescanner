// scannerModules.js
// Vollständige Sammel- und Analyse-Module für deinen Marketing/Compliance-Scanner.
// ES-Module Syntax. Keine Extra-Dependencies außer Playwright in server.js.

const TOOL_PATTERNS = [
  { name: "Google Analytics 4", category: "analytics", test: url =>
      /https:\/\/(www\.|region\d+\.)?google-analytics\.com\/g\/collect/.test(url) ||
      /https:\/\/www\.google-analytics\.com\/collect\?v=2/.test(url)
  },
  { name: "Google Tag Manager", category: "tagmanager", test: url =>
      /https:\/\/www\.googletagmanager\.com\/gtm\.js\?id=GTM-/.test(url) ||
      /https:\/\/www\.googletagmanager\.com\/gtag\/js\?id=G-/.test(url)
  },
  { name: "Google Ads", category: "ads", test: url =>
      /https:\/\/www\.googleadservices\.com\/pagead\/conversion/.test(url) ||
      /https:\/\/www\.googleadservices\.com\/gclid/.test(url)
  },
  { name: "Meta Pixel", category: "ads", test: url =>
      /https:\/\/www\.facebook\.com\/tr\?/.test(url) ||
      /https:\/\/connect\.facebook\.net\//.test(url)
  },
  { name: "LinkedIn Insight", category: "ads", test: url =>
      /https:\/\/px\.ads\.linkedin\.com\//.test(url) ||
      /https:\/\/snap\.licdn\.com\//.test(url)
  },
  { name: "Hotjar", category: "ux", test: url =>
      /https:\/\/(script|static)\.hotjar\.com\//.test(url) ||
      /https:\/\/(insights|events)\.hotjar\.com\//.test(url)
  },
  { name: "Kameleoon", category: "abtest", test: url =>
      /https:\/\/(data|eu-data)\.kameleoon\.eu\//.test(url) ||
      /https:\/\/.*\.kameleoon\.(io|com)\//.test(url)
  },
  { name: "YouTube", category: "media", test: url =>
      /https:\/\/www\.youtube-nocookie\.com\/embed\//.test(url)
  },
  { name: "Google Maps", category: "maps", test: url =>
      /https:\/\/maps\.googleapis\.com\//.test(url) ||
      /https:\/\/maps\.gstatic\.com\//.test(url) ||
      /https:\/\/maps\.googleapis\.com\/maps-api-v3/.test(url)
  },
];

const KNOWN_CONSOLE_PATTERNS = [
  {
    name: "CSP Refused",
    type: "csp",
    severity: "critical",
    detect: text => /Refused to (connect|load|frame|font)/i.test(text) && /Content Security Policy/i.test(text),
    extract: text => {
      const url = (text.match(/'(https?:\/\/[^']+)'/) || [])[1] || null;
      const directive = (text.match(/directive:\s*"([^"]+)"/i) || [])[1] || null;
      return { url, directive };
    }
  },
  {
    name: "Google Maps InvalidValueError",
    type: "js_error",
    severity: "critical",
    detect: text => /InvalidValueError: not an instance of HTMLInputElement/i.test(text),
    extract: () => ({ hint: "Google Maps Places Autocomplete benötigt ein echtes <input>-Element." })
  },
  {
    name: "CMP vendorConsents undefined",
    type: "js_error",
    severity: "critical",
    detect: text => /Cannot use 'in' operator to search for 'vendorConsents' in undefined/i.test(text),
    extract: () => ({ hint: "TCF-API wird zu früh/ohne gültiges tcData aufgerufen." })
  },
  {
    name: "Maps loading warning",
    type: "performance",
    severity: "warning",
    detect: text => /Google Maps JavaScript API has been loaded directly without loading=async/i.test(text),
    extract: () => ({ hint: "Maps Script asynchron laden (loading=async) für bessere Performance." })
  },
  {
    name: "Font data: blocked",
    type: "csp",
    severity: "warning",
    detect: text => /Refused to load the font 'data:font/i.test(text),
    extract: () => ({ directive: "font-src", hint: "Entweder font-src data: erlauben oder Fonts per HTTPS ausliefern." })
  }
];

const nowIso = () => new Date().toISOString();
const truncate = (s, n = 400) => (s && s.length > n ? s.slice(0, n) + "…" : s || "");

function classifyUrl(url) {
  for (const p of TOOL_PATTERNS) {
    if (p.test(url)) return { toolName: p.name, category: p.category };
  }
  return null;
}

export function attachAllCollectors(page, context, options = {}) {
  const sessionLabel = options.sessionLabel || "default";

  const consoleEvents = [];
  const networkRequests = [];
  const networkResponses = [];
  const headerSnapshots = [];
  const errors = [];
  const infos = [];

  const onConsole = msg => {
    const text = msg.text();
    const type = msg.type();
    if (type === "error" || type === "warning") {
      const base = { kind: "console", level: type, text, session: sessionLabel, timestamp: nowIso() };
      const match = KNOWN_CONSOLE_PATTERNS.find(p => p.detect(text));
      if (match) {
        const extra = match.extract(text) || {};
        consoleEvents.push({
          ...base,
          classified: true,
          type: match.type,
          severity: match.severity,
          name: match.name,
          ...extra
        });
      } else {
        consoleEvents.push({ ...base, classified: false });
      }
    }
  };

  const onRequestFailed = req => {
    const url = req.url();
    const cls = classifyUrl(url);
    networkRequests.push({
      kind: "network",
      phase: "failed",
      url,
      method: req.method(),
      failure: req.failure()?.errorText || "unknown",
      toolName: cls?.toolName || null,
      category: cls?.category || "network",
      session: sessionLabel,
      timestamp: nowIso()
    });
  };

  const onRequestFinished = async req => {
    const url = req.url();
    const cls = classifyUrl(url);
    try {
      const resp = await req.response();
      if (!resp) return;
      const status = resp.status();
      const headers = resp.headers();
      networkResponses.push({
        kind: "network",
        phase: "finished",
        url,
        method: req.method(),
        status,
        headers,
        toolName: cls?.toolName || null,
        category: cls?.category || "network",
        session: sessionLabel,
        timestamp: nowIso()
      });
      const ct = headers["content-type"] || "";
      if (status && /text\/html/i.test(ct)) {
        headerSnapshots.push({
          url,
          status,
          headers,
          session: sessionLabel,
          timestamp: nowIso()
        });
      }
    } catch (e) {
      errors.push({ where: "onRequestFinished", e: String(e) });
    }
  };

  const onResponse = async resp => {
    try {
      const url = resp.url();
      const status = resp.status();
      const headers = resp.headers();
      const cls = classifyUrl(url);
      networkResponses.push({
        kind: "response",
        url,
        status,
        headers,
        toolName: cls?.toolName || null,
        category: cls?.category || "network",
        session: sessionLabel,
        timestamp: nowIso()
      });
    } catch (e) {
      errors.push({ where: "onResponse", e: String(e) });
    }
  };

  page.on("console", onConsole);
  page.on("requestfailed", onRequestFailed);
  page.on("requestfinished", onRequestFinished);
  page.on("response", onResponse);

  async function stopAndCollect() {
    page.off("console", onConsole);
    page.off("requestfailed", onRequestFailed);
    page.off("requestfinished", onRequestFinished);
    page.off("response", onResponse);

    return {
      session: sessionLabel,
      consoleEvents,
      networkRequests,
      networkResponses,
      headerSnapshots,
      infos,
      errors
    };
  }

  return { stopAndCollect };
}

export async function snapshotCookies(context, { sessionLabel = "default" } = {}) {
  const cookies = await context.cookies();
  return { session: sessionLabel, kind: "cookies", cookies };
}

export async function snapshotStorage(page, { sessionLabel = "default" } = {}) {
  const local = await page.evaluate(() => {
    const out = {};
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      out[k] = localStorage.getItem(k);
    }
    return out;
  });
  const session = await page.evaluate(() => {
    const out = {};
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      out[k] = sessionStorage.getItem(k);
    }
    return out;
  });
  const indexedDBs = await page.evaluate(async () => {
    if (indexedDB && indexedDB.databases) {
      try {
        const dbs = await indexedDB.databases();
        return dbs.map(d => ({ name: d.name || null, version: d.version || null }));
      } catch { return []; }
    }
    return [];
  });
  return { session: sessionLabel, kind: "storage", localStorage: local, sessionStorage: session, indexedDBs };
}

export async function scanDOM(page, { sessionLabel = "default" } = {}) {
  const scripts = await page.evaluate(() => {
    return Array.from(document.scripts || []).map(s => ({
      src: s.src || null,
      async: !!s.async,
      defer: !!s.defer,
      type: s.type || null,
      inlineBytes: s.src ? 0 : (s.textContent ? s.textContent.length : 0)
    }));
  });
  const detectedTools = [];
  for (const s of scripts) {
    if (!s.src) continue;
    const cls = classifyUrl(s.src);
    if (cls) detectedTools.push({ toolName: cls.toolName, category: cls.category, src: s.src });
  }
  return { session: sessionLabel, kind: "dom", scripts, detectedTools };
}

export async function scanDataLayerAndConsent(page, { sessionLabel = "default" } = {}) {
  const dataLayer = await page.evaluate(() => {
    const dl = (window && window.dataLayer) ? Array.from(window.dataLayer) : [];
    return dl;
  });
  const consentStatus = await page.evaluate(async () => {
    const out = { tcfAvailable: false, tcString: null, eventStatus: null, gdprApplies: null };
    try {
      if (typeof window.__tcfapi === "function") {
        out.tcfAvailable = true;
        await new Promise(resolve => {
          window.__tcfapi("addEventListener", 2, (tcData, success) => {
            if (success && tcData) {
              out.tcString = tcData.tcString || null;
              out.eventStatus = tcData.eventStatus || null;
              out.gdprApplies = typeof tcData.gdprApplies === "boolean" ? tcData.gdprApplies : null;
            }
            resolve();
          });
        });
      }
    } catch {}
    return out;
  });
  return { session: sessionLabel, kind: "consent", dataLayer, consentStatus };
}

export function extractTopDocumentHeaders(collectorResult) {
  const htmls = (collectorResult?.headerSnapshots || []).filter(h => {
    const ct = (h.headers["content-type"] || "");
    return /text\/html/i.test(ct) && h.status >= 200 && h.status < 400;
  });
  if (!htmls.length) return null;
  const top = htmls[0];
  const csp = top.headers["content-security-policy"] || top.headers["content-security-policy-report-only"] || null;
  return { session: collectorResult.session, url: top.url, status: top.status, headers: top.headers, csp };
}

export function parseCSP(cspString) {
  if (!cspString) return null;
  const directives = {};
  cspString.split(";").forEach(part => {
    const seg = part.trim();
    if (!seg) return;
    const [name, ...vals] = seg.split(/\s+/);
    directives[name] = vals;
  });
  return directives;
}

export async function snapshotPerformance(page, { sessionLabel = "default" } = {}) {
  const perf = await page.evaluate(() => {
    const nav = performance.getEntriesByType("navigation")[0];
    const fcp = performance.getEntriesByName("first-contentful-paint")[0]?.startTime || null;
    const tbtLike = (() => {
      const domComplete = nav?.domComplete || null;
      return (fcp && domComplete) ? Math.max(0, domComplete - fcp - 100) : null;
    })();
    return {
      timing: nav ? {
        startTime: nav.startTime,
        domContentLoaded: nav.domContentLoadedEventEnd,
        loadEventEnd: nav.loadEventEnd,
        domInteractive: nav.domInteractive,
        responseEnd: nav.responseEnd
      } : null,
      tbtApprox: tbtLike,
      fcp
    };
  });
  return { session: sessionLabel, kind: "performance", ...perf };
}

export async function takeScreenshot(page, path) {
  await page.screenshot({ path, fullPage: true });
  return { kind: "screenshot", path, timestamp: nowIso() };
}

export function analyzeFindings(collectors, snapshots = {}) {
  const findings = [];

  for (const ev of collectors.consoleEvents || []) {
    if (ev.classified) {
      findings.push({
        type: ev.type,
        severity: ev.severity,
        session: ev.session,
        name: ev.name,
        originalMessage: truncate(ev.text, 800),
        evidence: { hint: ev.hint || null, directive: ev.directive || null },
        source: "console"
      });
    } else {
      findings.push({
        type: "console_warning",
        severity: ev.level === "error" ? "error" : "warning",
        session: ev.session,
        name: "Console Message",
        originalMessage: truncate(ev.text, 800),
        evidence: {},
        source: "console"
      });
    }
  }

  for (const req of collectors.networkRequests || []) {
    findings.push({
      type: "network_error",
      severity: "warning",
      session: req.session,
      toolName: req.toolName,
      category: req.category,
      url: req.url,
      originalMessage: `Request failed: ${req.failure}`,
      source: "network"
    });
  }

  for (const resp of collectors.networkResponses || []) {
    const isHit = resp.status >= 200 && resp.status < 400;
    if (resp.toolName) {
      findings.push({
        type: "tracking_hit",
        severity: isHit ? "info" : "warning",
        session: resp.session,
        toolName: resp.toolName,
        category: resp.category,
        url: resp.url,
        status: resp.status,
        source: "network"
      });
    }
  }

  if (snapshots.topHeaders?.csp) {
    const d = parseCSP(snapshots.topHeaders.csp);
    findings.push({
      type: "csp_header",
      severity: "info",
      session: collectors.session,
      originalMessage: `CSP detected`,
      evidence: { csp: snapshots.topHeaders.csp, parsed: d },
      source: "headers"
    });
  }

  if (snapshots.cookies?.cookies?.length) {
    findings.push({
      type: "cookies_snapshot",
      severity: "info",
      session: collectors.session,
      evidence: { count: snapshots.cookies.cookies.length },
      source: "cookies"
    });
  }

  if (snapshots.storage) {
    const localCount = Object.keys(snapshots.storage.localStorage || {}).length;
    const sessionCount = Object.keys(snapshots.storage.sessionStorage || {}).length;
    const idbCount = (snapshots.storage.indexedDBs || []).length;
    findings.push({
      type: "storage_snapshot",
      severity: "info",
      session: collectors.session,
      evidence: { localCount, sessionCount, idbCount },
      source: "storage"
    });
  }

  if (snapshots.dom?.detectedTools?.length) {
    for (const t of snapshots.dom.detectedTools) {
      findings.push({
        type: "script_present",
        severity: "info",
        session: collectors.session,
        toolName: t.toolName,
        category: t.category,
        url: t.src,
        source: "dom"
      });
    }
  }

  if (snapshots.consent) {
    findings.push({
      type: "consent_status",
      severity: "info",
      session: collectors.session,
      evidence: {
        tcfAvailable: snapshots.consent.consentStatus?.tcfAvailable || false,
        eventStatus: snapshots.consent.consentStatus?.eventStatus || null,
        tcString: truncate(snapshots.consent.consentStatus?.tcString, 60),
        dataLayerLen: (snapshots.consent.dataLayer || []).length
      },
      source: "consent"
    });
  }

  if (snapshots.performance) {
    findings.push({
      type: "performance_snapshot",
      severity: "info",
      session: collectors.session,
      evidence: snapshots.performance,
      source: "performance"
    });
  }

  // NEUE SECURITY FEATURES FINDINGS
  if (snapshots.securityHeaders) {
    findings.push({
      type: "security_headers",
      severity: snapshots.securityHeaders.missing.length > 0 ? "warning" : "info",
      session: collectors.session,
      evidence: {
        score: snapshots.securityHeaders.score,
        missing: snapshots.securityHeaders.missing,
        headers: snapshots.securityHeaders.headers
      },
      source: "security_headers"
    });
  }

  if (snapshots.mixedContent && snapshots.mixedContent.detected) {
    findings.push({
      type: "mixed_content",
      severity: snapshots.mixedContent.severity,
      session: collectors.session,
      evidence: {
        count: snapshots.mixedContent.count,
        items: snapshots.mixedContent.items
      },
      source: "mixed_content"
    });
  }

  if (snapshots.productionErrors && snapshots.productionErrors.count > 0) {
    findings.push({
      type: "production_errors",
      severity: snapshots.productionErrors.hasCritical ? "critical" : "warning",
      session: collectors.session,
      evidence: {
        count: snapshots.productionErrors.count,
        errors: snapshots.productionErrors.errors
      },
      source: "production_errors"
    });
  }

  if (snapshots.thirdPartyPerf && snapshots.thirdPartyPerf.warning) {
    findings.push({
      type: "third_party_performance",
      severity: snapshots.thirdPartyPerf.slowScripts > 5 ? "warning" : "info",
      session: collectors.session,
      evidence: {
        totalScripts: snapshots.thirdPartyPerf.totalScripts,
        slowScripts: snapshots.thirdPartyPerf.slowScripts,
        totalTime: snapshots.thirdPartyPerf.totalTime,
        totalSize: snapshots.thirdPartyPerf.totalSize,
        topScripts: snapshots.thirdPartyPerf.scripts.slice(0, 5)
      },
      source: "third_party_performance"
    });
  }

  if (snapshots.vulnerableLibs && snapshots.vulnerableLibs.vulnerable > 0) {
    findings.push({
      type: "vulnerable_libraries",
      severity: snapshots.vulnerableLibs.severity,
      session: collectors.session,
      evidence: {
        vulnerable: snapshots.vulnerableLibs.vulnerable,
        libraries: snapshots.vulnerableLibs.libraries
      },
      source: "vulnerable_libraries"
    });
  }

  if (snapshots.cookieBanner) {
    findings.push({
      type: "cookie_banner_validation",
      severity: snapshots.cookieBanner.severity,
      session: collectors.session,
      evidence: {
        present: snapshots.cookieBanner.present,
        compliance: snapshots.cookieBanner.compliance,
        hasAcceptButton: snapshots.cookieBanner.hasAcceptButton,
        hasRejectButton: snapshots.cookieBanner.hasRejectButton
      },
      source: "cookie_banner"
    });
  }

  if (snapshots.renderBlocking && snapshots.renderBlocking.total > 0) {
    findings.push({
      type: "render_blocking",
      severity: snapshots.renderBlocking.severity,
      session: collectors.session,
      evidence: {
        total: snapshots.renderBlocking.total,
        blockingScripts: snapshots.renderBlocking.blockingScripts,
        blockingStylesheets: snapshots.renderBlocking.blockingStylesheets,
        resources: snapshots.renderBlocking.resources.slice(0, 5)
      },
      source: "render_blocking"
    });
  }

  if (snapshots.fingerprinting && snapshots.fingerprinting.detected) {
    findings.push({
      type: "fingerprinting_detection",
      severity: snapshots.fingerprinting.severity,
      session: collectors.session,
      evidence: {
        count: snapshots.fingerprinting.count,
        methods: snapshots.fingerprinting.methods
      },
      source: "fingerprinting"
    });
  }

  // ===================== 10 NEUE TECHNISCHE PRÜFUNGEN IN FINDINGS =====================

  // 1. Broken Resources
  if (snapshots.brokenResources && snapshots.brokenResources.count > 0) {
    findings.push({
      type: "broken_resources",
      severity: snapshots.brokenResources.severity,
      session: collectors.session,
      evidence: {
        count: snapshots.brokenResources.count,
        details: snapshots.brokenResources.details,
        grouped: snapshots.brokenResources.grouped
      },
      source: "network"
    });
  }

  // 2. JavaScript Errors
  if (snapshots.jsErrors && snapshots.jsErrors.count > 0) {
    findings.push({
      type: "javascript_runtime_errors",
      severity: snapshots.jsErrors.severity,
      session: collectors.session,
      evidence: {
        count: snapshots.jsErrors.count,
        errors: snapshots.jsErrors.errors
      },
      source: "console"
    });
  }

  // 3. CORS Issues
  if (snapshots.corsIssues && snapshots.corsIssues.count > 0) {
    findings.push({
      type: "cors_failures",
      severity: snapshots.corsIssues.severity,
      session: collectors.session,
      evidence: {
        count: snapshots.corsIssues.count,
        errors: snapshots.corsIssues.errors,
        failedRequests: snapshots.corsIssues.failedRequests
      },
      source: "network"
    });
  }

  // 4. Service Worker
  if (snapshots.serviceWorker) {
    findings.push({
      type: "service_worker_status",
      severity: snapshots.serviceWorker.hasErrors ? 'high' : 'info',
      session: collectors.session,
      evidence: snapshots.serviceWorker,
      source: "browser_api"
    });
  }

  // 5. Form Validation
  if (snapshots.formValidation && snapshots.formValidation.issueCount > 0) {
    findings.push({
      type: "form_validation_issues",
      severity: snapshots.formValidation.severity,
      session: collectors.session,
      evidence: {
        totalForms: snapshots.formValidation.totalForms,
        issueCount: snapshots.formValidation.issueCount,
        issues: snapshots.formValidation.issues
      },
      source: "dom"
    });
  }

  // 6. Slow Resources
  if (snapshots.slowResources && snapshots.slowResources.count > 0) {
    findings.push({
      type: "slow_loading_resources",
      severity: snapshots.slowResources.severity,
      session: collectors.session,
      evidence: {
        count: snapshots.slowResources.count,
        resources: snapshots.slowResources.resources
      },
      source: "performance"
    });
  }

  // 7. Image Optimization
  if (snapshots.imageOptimization && (snapshots.imageOptimization.largeCount > 0 || snapshots.imageOptimization.missingAltCount > 0)) {
    findings.push({
      type: "image_optimization_issues",
      severity: snapshots.imageOptimization.severity,
      session: collectors.session,
      evidence: {
        totalImages: snapshots.imageOptimization.totalImages,
        largeCount: snapshots.imageOptimization.largeCount,
        missingAltCount: snapshots.imageOptimization.missingAltCount,
        largeImages: snapshots.imageOptimization.largeImages,
        missingAlt: snapshots.imageOptimization.missingAlt
      },
      source: "dom"
    });
  }

  // 8. Font Loading
  if (snapshots.fontLoading && snapshots.fontLoading.failedCount > 0) {
    findings.push({
      type: "font_loading_failures",
      severity: snapshots.fontLoading.severity,
      session: collectors.session,
      evidence: {
        totalFonts: snapshots.fontLoading.totalFonts,
        failedCount: snapshots.fontLoading.failedCount,
        failed: snapshots.fontLoading.failed
      },
      source: "performance"
    });
  }

  // 9. Memory Usage
  if (snapshots.memoryUsage && snapshots.memoryUsage.supported) {
    findings.push({
      type: "memory_usage",
      severity: snapshots.memoryUsage.severity,
      session: collectors.session,
      evidence: {
        usagePercent: snapshots.memoryUsage.usagePercent,
        usedJSHeapSize: snapshots.memoryUsage.usedJSHeapSize,
        jsHeapSizeLimit: snapshots.memoryUsage.jsHeapSizeLimit,
        warning: snapshots.memoryUsage.warning
      },
      source: "performance"
    });
  }

  // 10. Redirect Chains
  if (snapshots.redirectChains && snapshots.redirectChains.chainCount > 0) {
    findings.push({
      type: "redirect_chains",
      severity: snapshots.redirectChains.severity,
      session: collectors.session,
      evidence: {
        totalRedirects: snapshots.redirectChains.totalRedirects,
        chainCount: snapshots.redirectChains.chainCount,
        chains: snapshots.redirectChains.chains
      },
      source: "network"
    });
  }

  return findings;
}

// ===================== NEUE SECURITY FEATURES =====================

// 1. Security Headers Check
export async function checkSecurityHeaders(topHeaders, { sessionLabel = "default" } = {}) {
  if (!topHeaders?.headers) return null;

  const headers = topHeaders.headers;
  const requiredHeaders = {
    'x-frame-options': {
      present: !!headers['x-frame-options'],
      value: headers['x-frame-options'],
      severity: 'high',
      description: 'Schützt vor Clickjacking-Angriffen'
    },
    'x-content-type-options': {
      present: !!headers['x-content-type-options'],
      value: headers['x-content-type-options'],
      severity: 'medium',
      description: 'Verhindert MIME-Type-Sniffing'
    },
    'strict-transport-security': {
      present: !!headers['strict-transport-security'],
      value: headers['strict-transport-security'],
      severity: 'high',
      description: 'Erzwingt HTTPS-Verbindungen'
    },
    'x-xss-protection': {
      present: !!headers['x-xss-protection'],
      value: headers['x-xss-protection'],
      severity: 'medium',
      description: 'XSS-Filter im Browser (legacy)'
    },
    'referrer-policy': {
      present: !!headers['referrer-policy'],
      value: headers['referrer-policy'],
      severity: 'low',
      description: 'Kontrolliert Referrer-Informationen'
    },
    'permissions-policy': {
      present: !!headers['permissions-policy'],
      value: headers['permissions-policy'],
      severity: 'medium',
      description: 'Kontrolliert Browser-Features'
    }
  };

  const missing = Object.entries(requiredHeaders)
    .filter(([key, info]) => !info.present)
    .map(([key, info]) => ({ header: key, severity: info.severity, description: info.description }));

  return {
    session: sessionLabel,
    kind: "security_headers",
    headers: requiredHeaders,
    missing,
    score: ((Object.keys(requiredHeaders).length - missing.length) / Object.keys(requiredHeaders).length * 100).toFixed(0)
  };
}

// 2. Mixed Content Detection
export function detectMixedContent(networkResponses, topHeaders, { sessionLabel = "default" } = {}) {
  const pageUrl = topHeaders?.url || '';
  const isHttpsPage = pageUrl.startsWith('https://');

  if (!isHttpsPage) {
    return { session: sessionLabel, kind: "mixed_content", applicable: false, reason: "Page not HTTPS" };
  }

  const mixedContent = networkResponses
    .filter(resp => resp.url && resp.url.startsWith('http://'))
    .map(resp => ({
      url: resp.url,
      resourceType: resp.category || 'unknown',
      blocked: resp.status === 0 || resp.status >= 400
    }));

  return {
    session: sessionLabel,
    kind: "mixed_content",
    applicable: true,
    detected: mixedContent.length > 0,
    count: mixedContent.length,
    items: mixedContent.slice(0, 20),
    severity: mixedContent.length > 0 ? 'high' : 'none'
  };
}

// 3. JavaScript Production Errors Detection
export function detectProductionErrors(consoleEvents, { sessionLabel = "default" } = {}) {
  const productionErrorPatterns = [
    { pattern: /sourceMappingURL|\.map/i, type: 'sourcemap_missing', severity: 'low' },
    { pattern: /minified|uglified|bundled/i, type: 'minification_error', severity: 'medium' },
    { pattern: /webpack|parcel|rollup|vite/i, type: 'bundler_error', severity: 'medium' },
    { pattern: /undefined is not|cannot read property.*undefined/i, type: 'null_reference', severity: 'high' },
    { pattern: /script error/i, type: 'cors_script_error', severity: 'medium' },
    { pattern: /out of memory/i, type: 'memory_error', severity: 'critical' },
    { pattern: /maximum call stack/i, type: 'stack_overflow', severity: 'critical' }
  ];

  const detectedErrors = consoleEvents
    .filter(ev => ev.level === 'error')
    .map(ev => {
      const text = ev.text || '';
      const matches = productionErrorPatterns.filter(p => p.pattern.test(text));
      return matches.length > 0 ? {
        message: truncate(text, 300),
        types: matches.map(m => m.type),
        severity: matches.reduce((max, m) => {
          const levels = { critical: 4, high: 3, medium: 2, low: 1 };
          return levels[m.severity] > levels[max] ? m.severity : max;
        }, 'low'),
        timestamp: ev.timestamp
      } : null;
    })
    .filter(Boolean);

  return {
    session: sessionLabel,
    kind: "production_errors",
    count: detectedErrors.length,
    errors: detectedErrors.slice(0, 10),
    hasCritical: detectedErrors.some(e => e.severity === 'critical')
  };
}

// 4. Third-Party Script Performance Analysis
export async function analyzeThirdPartyPerformance(page, { sessionLabel = "default" } = {}) {
  const resourceTimings = await page.evaluate(() => {
    const entries = performance.getEntriesByType('resource');
    return entries
      .filter(e => e.initiatorType === 'script' || e.name.endsWith('.js'))
      .map(e => ({
        url: e.name,
        duration: e.duration,
        size: e.transferSize || 0,
        startTime: e.startTime,
        dns: e.domainLookupEnd - e.domainLookupStart,
        tcp: e.connectEnd - e.connectStart,
        download: e.responseEnd - e.responseStart,
        blocked: e.domainLookupStart - e.fetchStart
      }));
  });

  const thirdParty = resourceTimings.filter(r => {
    try {
      const scriptHost = new URL(r.url).hostname;
      const pageHost = new URL(window.location.href).hostname;
      return scriptHost !== pageHost;
    } catch {
      return false;
    }
  }).map(r => {
    const cls = classifyUrl(r.url);
    return { ...r, toolName: cls?.toolName || null, category: cls?.category || 'unknown' };
  });

  const slowScripts = thirdParty.filter(s => s.duration > 500);
  const totalThirdPartyTime = thirdParty.reduce((sum, s) => sum + s.duration, 0);
  const totalThirdPartySize = thirdParty.reduce((sum, s) => sum + s.size, 0);

  return {
    session: sessionLabel,
    kind: "third_party_performance",
    totalScripts: thirdParty.length,
    slowScripts: slowScripts.length,
    totalTime: Math.round(totalThirdPartyTime),
    totalSize: totalThirdPartySize,
    scripts: thirdParty.sort((a, b) => b.duration - a.duration).slice(0, 15),
    warning: slowScripts.length > 0
  };
}

// 5. Vulnerable Libraries Detection
export async function detectVulnerableLibraries(page, { sessionLabel = "default" } = {}) {
  const knownVulnerablePatterns = [
    { lib: 'jQuery', versions: ['1.', '2.', '3.0.', '3.1.', '3.2.', '3.3.', '3.4.0', '3.4.1'], pattern: /jquery[.-](\d+\.\d+\.\d+)/i },
    { lib: 'Angular', versions: ['1.'], pattern: /angular[.-](\d+\.\d+)/i },
    { lib: 'Moment.js', versions: ['2.29.3', '2.29.2', '2.29.1'], pattern: /moment[.-](\d+\.\d+\.\d+)/i },
    { lib: 'Lodash', versions: ['4.17.20', '4.17.19', '4.17.15'], pattern: /lodash[.-](\d+\.\d+\.\d+)/i },
    { lib: 'Bootstrap', versions: ['3.', '4.0.', '4.1.', '4.2.', '4.3.0'], pattern: /bootstrap[.-](\d+\.\d+\.\d+)/i }
  ];

  const detectedLibs = await page.evaluate((patterns) => {
    const scripts = Array.from(document.scripts);
    const detected = [];

    scripts.forEach(script => {
      const src = script.src || '';
      const content = script.textContent || '';

      patterns.forEach(({ lib, versions, pattern: patternStr }) => {
        const pattern = new RegExp(patternStr.source, patternStr.flags);
        const match = src.match(pattern) || content.substring(0, 1000).match(pattern);

        if (match && match[1]) {
          const version = match[1];
          const isVulnerable = versions.some(v => version.startsWith(v));

          if (isVulnerable) {
            detected.push({
              library: lib,
              version,
              source: src || 'inline',
              vulnerable: true
            });
          }
        }
      });
    });

    // Check window globals
    if (typeof window.jQuery !== 'undefined' && window.jQuery.fn) {
      const jqVersion = window.jQuery.fn.jquery;
      detected.push({ library: 'jQuery', version: jqVersion, source: 'window.jQuery', vulnerable: /^[123]\.|^3\.[0-4]\.[01]/.test(jqVersion) });
    }

    if (typeof window.angular !== 'undefined' && window.angular.version) {
      const ngVersion = window.angular.version.full;
      detected.push({ library: 'Angular', version: ngVersion, source: 'window.angular', vulnerable: /^1\./.test(ngVersion) });
    }

    return detected;
  }, knownVulnerablePatterns);

  const vulnerableLibs = detectedLibs.filter(lib => lib.vulnerable);

  return {
    session: sessionLabel,
    kind: "vulnerable_libraries",
    detected: detectedLibs.length,
    vulnerable: vulnerableLibs.length,
    libraries: vulnerableLibs,
    severity: vulnerableLibs.length > 0 ? 'high' : 'none'
  };
}

// 6. Advanced Cookie Banner Validation
export async function validateCookieBanner(page, { sessionLabel = "default" } = {}) {
  const bannerInfo = await page.evaluate(() => {
    const selectors = [
      '[class*="cookie"][class*="banner"]',
      '[class*="consent"]',
      '[id*="cookie"][id*="banner"]',
      '[id*="consent"]',
      '.cookie-notice',
      '#cookie-notice',
      '[role="dialog"][aria-label*="cookie" i]',
      '[role="dialog"][aria-label*="consent" i]'
    ];

    let banner = null;
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.offsetParent !== null) {
        banner = el;
        break;
      }
    }

    if (!banner) return { present: false };

    const buttons = Array.from(banner.querySelectorAll('button, [role="button"], a[href], input[type="button"]'));
    const acceptBtn = buttons.find(b => /accept|zustimmen|einverstanden|alle.*akzept/i.test(b.textContent || ''));
    const rejectBtn = buttons.find(b => /reject|ablehnen|nur.*notwendig|necessary.*only/i.test(b.textContent || ''));
    const settingsBtn = buttons.find(b => /settings|einstellungen|customize|anpassen/i.test(b.textContent || ''));

    return {
      present: true,
      visible: banner.offsetParent !== null,
      hasAcceptButton: !!acceptBtn,
      hasRejectButton: !!rejectBtn,
      hasSettingsButton: !!settingsBtn,
      buttonCount: buttons.length,
      hasPrivacyLink: !!banner.querySelector('a[href*="privacy"], a[href*="datenschutz"]'),
      position: window.getComputedStyle(banner).position,
      zIndex: window.getComputedStyle(banner).zIndex
    };
  });

  const compliance = {
    gdprCompliant: bannerInfo.present && bannerInfo.hasAcceptButton && bannerInfo.hasRejectButton,
    issues: []
  };

  if (!bannerInfo.present) compliance.issues.push('Kein Cookie-Banner gefunden');
  if (bannerInfo.present && !bannerInfo.hasRejectButton) compliance.issues.push('Keine Ablehnen-Option gefunden');
  if (bannerInfo.present && !bannerInfo.hasAcceptButton) compliance.issues.push('Keine Akzeptieren-Option gefunden');
  if (bannerInfo.present && !bannerInfo.hasPrivacyLink) compliance.issues.push('Kein Link zur Datenschutzerklärung');

  return {
    session: sessionLabel,
    kind: "cookie_banner_validation",
    ...bannerInfo,
    compliance,
    severity: compliance.gdprCompliant ? 'none' : 'high'
  };
}

// 7. Render-Blocking Resources Detection
export async function detectRenderBlockingResources(page, { sessionLabel = "default" } = {}) {
  const blockingResources = await page.evaluate(() => {
    const scripts = Array.from(document.scripts);
    const links = Array.from(document.querySelectorAll('link[rel="stylesheet"]'));

    const blocking = {
      scripts: scripts
        .filter(s => s.src && !s.async && !s.defer && s.compareDocumentPosition(document.body) & Node.DOCUMENT_POSITION_FOLLOWING)
        .map(s => ({
          url: s.src,
          inHead: s.parentElement?.tagName === 'HEAD',
          type: 'script'
        })),
      stylesheets: links
        .filter(l => !l.media || l.media === 'all' || l.media === 'screen')
        .map(l => ({
          url: l.href,
          media: l.media || 'all',
          type: 'stylesheet'
        }))
    };

    return blocking;
  });

  const totalBlocking = blockingResources.scripts.length + blockingResources.stylesheets.length;

  return {
    session: sessionLabel,
    kind: "render_blocking",
    blockingScripts: blockingResources.scripts.length,
    blockingStylesheets: blockingResources.stylesheets.length,
    total: totalBlocking,
    resources: [
      ...blockingResources.scripts,
      ...blockingResources.stylesheets
    ].slice(0, 20),
    severity: totalBlocking > 5 ? 'medium' : totalBlocking > 0 ? 'low' : 'none'
  };
}

// 8. Browser Fingerprinting Detection
export async function detectFingerprinting(page, { sessionLabel = "default" } = {}) {
  const fingerprintingSignals = await page.evaluate(() => {
    const signals = {
      canvasFingerprinting: false,
      webglFingerprinting: false,
      audioFingerprinting: false,
      fontFingerprinting: false,
      batteryAPI: false,
      deviceMemory: false,
      hardwareConcurrency: false,
      screenResolution: false
    };

    // Canvas Fingerprinting Detection
    const canvasProto = CanvasRenderingContext2D.prototype;
    if (canvasProto.getImageData.toString().includes('[native code]')) {
      // Check if canvas is being used in a fingerprinting way
      const testCanvas = document.createElement('canvas');
      if (testCanvas.getContext) signals.canvasFingerprinting = true;
    }

    // WebGL Fingerprinting
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) signals.webglFingerprinting = true;
      }
    } catch (e) {}

    // Audio Fingerprinting
    if (typeof AudioContext !== 'undefined' || typeof webkitAudioContext !== 'undefined') {
      signals.audioFingerprinting = true;
    }

    // Font Fingerprinting (check if font detection is being used)
    if (document.fonts && document.fonts.check) {
      signals.fontFingerprinting = true;
    }

    // Battery API
    if (navigator.getBattery) signals.batteryAPI = true;

    // Device Memory
    if (navigator.deviceMemory) signals.deviceMemory = true;

    // Hardware Concurrency
    if (navigator.hardwareConcurrency) signals.hardwareConcurrency = true;

    // Screen Resolution
    if (window.screen.width && window.screen.height && window.screen.colorDepth) {
      signals.screenResolution = true;
    }

    return signals;
  });

  const fingerprintingMethods = Object.entries(fingerprintingSignals)
    .filter(([key, value]) => value)
    .map(([key]) => key);

  return {
    session: sessionLabel,
    kind: "fingerprinting_detection",
    detected: fingerprintingMethods.length > 0,
    methods: fingerprintingMethods,
    count: fingerprintingMethods.length,
    signals: fingerprintingSignals,
    severity: fingerprintingMethods.length > 3 ? 'medium' : fingerprintingMethods.length > 0 ? 'low' : 'none'
  };
}

// ===================== 10 NEUE TECHNISCHE PRÜFUNGEN =====================

// 1. Broken Links & Resources (404, 500, etc.)
export async function detectBrokenResources(networkResponses, { sessionLabel = "default" } = {}) {
  const broken = (networkResponses || []).filter(resp => {
    const status = resp.status;
    return status >= 400; // 4xx, 5xx errors
  });

  const grouped = {};
  broken.forEach(resp => {
    const statusKey = Math.floor(resp.status / 100) * 100; // 400, 500, etc.
    if (!grouped[statusKey]) grouped[statusKey] = [];
    grouped[statusKey].push({
      url: truncate(resp.url, 200),
      status: resp.status,
      category: resp.category || 'unknown'
    });
  });

  return {
    session: sessionLabel,
    kind: "broken_resources",
    count: broken.length,
    severity: broken.some(r => r.status >= 500) ? 'high' : broken.length > 0 ? 'medium' : 'none',
    grouped,
    details: broken.slice(0, 20).map(r => ({
      url: truncate(r.url, 200),
      status: r.status,
      category: r.category || 'unknown'
    }))
  };
}

// 2. JavaScript Runtime Errors (Uncaught Exceptions)
export function detectJavaScriptErrors(consoleEvents, { sessionLabel = "default" } = {}) {
  const jsErrors = (consoleEvents || []).filter(ev => {
    if (ev.level !== 'error') return false;
    const text = ev.text || '';
    return /Uncaught|TypeError|ReferenceError|SyntaxError|RangeError/i.test(text);
  });

  return {
    session: sessionLabel,
    kind: "javascript_errors",
    count: jsErrors.length,
    severity: jsErrors.length > 5 ? 'high' : jsErrors.length > 0 ? 'medium' : 'none',
    errors: jsErrors.slice(0, 15).map(e => ({
      message: truncate(e.text, 300),
      timestamp: e.timestamp
    }))
  };
}

// 3. CORS Failures
export function detectCORSIssues(consoleEvents, networkRequests, { sessionLabel = "default" } = {}) {
  const corsErrors = (consoleEvents || []).filter(ev => {
    const text = ev.text || '';
    return /CORS|Cross-Origin|Access-Control-Allow-Origin/i.test(text);
  });

  const corsFailedRequests = (networkRequests || []).filter(req => {
    return /CORS/i.test(req.failure || '');
  });

  return {
    session: sessionLabel,
    kind: "cors_issues",
    count: corsErrors.length + corsFailedRequests.length,
    severity: corsErrors.length + corsFailedRequests.length > 0 ? 'high' : 'none',
    errors: corsErrors.slice(0, 10).map(e => truncate(e.text, 300)),
    failedRequests: corsFailedRequests.slice(0, 10).map(r => truncate(r.url, 200))
  };
}

// 4. Service Worker Errors
export async function detectServiceWorkerIssues(page, { sessionLabel = "default" } = {}) {
  const swStatus = await page.evaluate(() => {
    if (!('serviceWorker' in navigator)) {
      return { supported: false, registered: false };
    }

    return navigator.serviceWorker.getRegistrations().then(registrations => {
      return {
        supported: true,
        registered: registrations.length > 0,
        count: registrations.length,
        scopes: registrations.map(r => r.scope)
      };
    }).catch(e => {
      return { supported: true, registered: false, error: String(e) };
    });
  });

  // Check for SW errors in console
  const swErrors = []; // Would need to be passed from consoleEvents

  return {
    session: sessionLabel,
    kind: "service_worker",
    ...swStatus,
    hasErrors: swErrors.length > 0,
    errors: swErrors
  };
}

// 5. Form Validation & Functionality
export async function validateForms(page, { sessionLabel = "default" } = {}) {
  const formAnalysis = await page.evaluate(() => {
    const forms = Array.from(document.querySelectorAll('form'));

    return forms.map(form => {
      const inputs = form.querySelectorAll('input, textarea, select');
      const hasAction = !!form.action && form.action !== window.location.href;
      const hasMethod = !!form.method;
      const hasValidation = Array.from(inputs).some(input =>
        input.hasAttribute('required') || input.hasAttribute('pattern')
      );
      const hasSubmitButton = !!form.querySelector('button[type="submit"], input[type="submit"]');

      return {
        action: form.action || null,
        method: form.method || 'get',
        inputCount: inputs.length,
        hasAction,
        hasMethod,
        hasValidation,
        hasSubmitButton,
        id: form.id || null,
        name: form.name || null
      };
    });
  });

  const issues = formAnalysis.filter(f =>
    !f.hasAction || !f.hasSubmitButton || f.inputCount === 0
  );

  return {
    session: sessionLabel,
    kind: "form_validation",
    totalForms: formAnalysis.length,
    issueCount: issues.length,
    severity: issues.length > 0 ? 'medium' : 'none',
    forms: formAnalysis,
    issues: issues
  };
}

// 6. Critical Resource Timeouts
export async function detectSlowResources(page, { sessionLabel = "default" } = {}) {
  const slowResources = await page.evaluate(() => {
    const entries = performance.getEntriesByType('resource');
    const slow = entries.filter(e => e.duration > 3000); // > 3s

    return slow.map(e => ({
      url: e.name,
      duration: Math.round(e.duration),
      type: e.initiatorType,
      size: e.transferSize || 0
    }));
  });

  return {
    session: sessionLabel,
    kind: "slow_resources",
    count: slowResources.length,
    severity: slowResources.length > 5 ? 'high' : slowResources.length > 0 ? 'medium' : 'none',
    resources: slowResources.slice(0, 15)
  };
}

// 7. Image Optimization Check
export async function analyzeImages(page, { sessionLabel = "default" } = {}) {
  const imageAnalysis = await page.evaluate(() => {
    const images = Array.from(document.querySelectorAll('img'));
    const largeImages = [];
    const missingAlt = [];

    images.forEach(img => {
      const naturalSize = img.naturalWidth * img.naturalHeight;
      const displaySize = img.width * img.height;
      const oversized = displaySize > 0 && naturalSize > displaySize * 2;

      if (oversized || naturalSize > 1920 * 1080) {
        largeImages.push({
          src: img.src,
          naturalWidth: img.naturalWidth,
          naturalHeight: img.naturalHeight,
          displayWidth: img.width,
          displayHeight: img.height,
          oversized
        });
      }

      if (!img.alt || img.alt.trim() === '') {
        missingAlt.push(img.src);
      }
    });

    return {
      totalImages: images.length,
      largeImages: largeImages.slice(0, 10),
      missingAlt: missingAlt.slice(0, 10)
    };
  });

  return {
    session: sessionLabel,
    kind: "image_optimization",
    totalImages: imageAnalysis.totalImages,
    largeCount: imageAnalysis.largeImages.length,
    missingAltCount: imageAnalysis.missingAlt.length,
    severity: imageAnalysis.largeImages.length > 5 ? 'medium' : 'low',
    largeImages: imageAnalysis.largeImages,
    missingAlt: imageAnalysis.missingAlt
  };
}

// 8. Font Loading Issues (FOIT/FOUT)
export async function analyzeFontLoading(page, { sessionLabel = "default" } = {}) {
  const fontAnalysis = await page.evaluate(() => {
    if (!document.fonts) return { supported: false };

    const fonts = Array.from(document.fonts);
    const loadedFonts = fonts.filter(f => f.status === 'loaded');
    const failedFonts = fonts.filter(f => f.status === 'error');

    return {
      supported: true,
      totalFonts: fonts.length,
      loadedCount: loadedFonts.length,
      failedCount: failedFonts.length,
      failed: failedFonts.map(f => f.family)
    };
  });

  return {
    session: sessionLabel,
    kind: "font_loading",
    ...fontAnalysis,
    severity: fontAnalysis.failedCount > 0 ? 'medium' : 'none'
  };
}

// 9. Memory Leaks Detection
export async function detectMemoryIssues(page, { sessionLabel = "default" } = {}) {
  const memoryInfo = await page.evaluate(() => {
    if (!performance.memory) return { supported: false };

    return {
      supported: true,
      usedJSHeapSize: performance.memory.usedJSHeapSize,
      totalJSHeapSize: performance.memory.totalJSHeapSize,
      jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
      usagePercent: Math.round((performance.memory.usedJSHeapSize / performance.memory.jsHeapSizeLimit) * 100)
    };
  });

  const highUsage = memoryInfo.supported && memoryInfo.usagePercent > 70;

  return {
    session: sessionLabel,
    kind: "memory_usage",
    ...memoryInfo,
    severity: highUsage ? 'high' : memoryInfo.usagePercent > 50 ? 'medium' : 'low',
    warning: highUsage ? 'High memory usage detected - possible memory leak' : null
  };
}

// 10. Redirect Chains
export function detectRedirectChains(networkResponses, { sessionLabel = "default" } = {}) {
  const redirects = (networkResponses || []).filter(resp => {
    return resp.status >= 300 && resp.status < 400;
  });

  const chains = {};
  redirects.forEach(resp => {
    const location = resp.headers?.location || resp.headers?.Location;
    if (location) {
      if (!chains[resp.url]) chains[resp.url] = [];
      chains[resp.url].push({ status: resp.status, to: location });
    }
  });

  const longChains = Object.entries(chains).filter(([url, chain]) => chain.length > 1);

  return {
    session: sessionLabel,
    kind: "redirect_chains",
    totalRedirects: redirects.length,
    chainCount: longChains.length,
    severity: longChains.length > 0 ? 'medium' : redirects.length > 5 ? 'low' : 'none',
    chains: longChains.slice(0, 10).map(([url, chain]) => ({
      from: truncate(url, 150),
      chain: chain
    }))
  };
}

// ===================== UPDATED collectAllForCurrentState =====================

export async function collectAllForCurrentState(page, context, options = {}) {
  const { sessionLabel = "default" } = options;
  const { stopAndCollect } = attachAllCollectors(page, context, { sessionLabel });

  await page.waitForLoadState("load").catch(() => {});
  await page.waitForTimeout(500);

  const [cookies, storage, dom, consent, performance] = await Promise.all([
    snapshotCookies(context, { sessionLabel }),
    snapshotStorage(page, { sessionLabel }),
    scanDOM(page, { sessionLabel }),
    scanDataLayerAndConsent(page, { sessionLabel }),
    snapshotPerformance(page, { sessionLabel })
  ]);

  const collectors = await stopAndCollect();
  const topHeaders = extractTopDocumentHeaders(collectors);

  // SECURITY FEATURES + 10 NEUE TECHNISCHE PRÜFUNGEN
  const [
    securityHeaders, mixedContent, productionErrors, thirdPartyPerf, vulnerableLibs,
    cookieBanner, renderBlocking, fingerprinting,
    // 10 neue Checks:
    brokenResources, jsErrors, corsIssues, serviceWorker, formValidation,
    slowResources, imageOptimization, fontLoading, memoryUsage, redirectChains
  ] = await Promise.all([
    checkSecurityHeaders(topHeaders, { sessionLabel }),
    Promise.resolve(detectMixedContent(collectors.networkResponses, topHeaders, { sessionLabel })),
    Promise.resolve(detectProductionErrors(collectors.consoleEvents, { sessionLabel })),
    analyzeThirdPartyPerformance(page, { sessionLabel }),
    detectVulnerableLibraries(page, { sessionLabel }),
    validateCookieBanner(page, { sessionLabel }),
    detectRenderBlockingResources(page, { sessionLabel }),
    detectFingerprinting(page, { sessionLabel }),
    // 10 neue Checks:
    Promise.resolve(detectBrokenResources(collectors.networkResponses, { sessionLabel })),
    Promise.resolve(detectJavaScriptErrors(collectors.consoleEvents, { sessionLabel })),
    Promise.resolve(detectCORSIssues(collectors.consoleEvents, collectors.networkRequests, { sessionLabel })),
    detectServiceWorkerIssues(page, { sessionLabel }),
    validateForms(page, { sessionLabel }),
    detectSlowResources(page, { sessionLabel }),
    analyzeImages(page, { sessionLabel }),
    analyzeFontLoading(page, { sessionLabel }),
    detectMemoryIssues(page, { sessionLabel }),
    Promise.resolve(detectRedirectChains(collectors.networkResponses, { sessionLabel }))
  ]);

  const findings = analyzeFindings(collectors, {
    cookies, storage, dom, consent, topHeaders, performance,
    securityHeaders, mixedContent, productionErrors, thirdPartyPerf,
    vulnerableLibs, cookieBanner, renderBlocking, fingerprinting,
    // 10 neue Checks:
    brokenResources, jsErrors, corsIssues, serviceWorker, formValidation,
    slowResources, imageOptimization, fontLoading, memoryUsage, redirectChains
  });

  return {
    session: sessionLabel,
    artifacts: {
      collectors, cookies, storage, dom, consent, topHeaders, performance,
      securityHeaders, mixedContent, productionErrors, thirdPartyPerf,
      vulnerableLibs, cookieBanner, renderBlocking, fingerprinting,
      // 10 neue Checks:
      brokenResources, jsErrors, corsIssues, serviceWorker, formValidation,
      slowResources, imageOptimization, fontLoading, memoryUsage, redirectChains
    },
    findings
  };
}
