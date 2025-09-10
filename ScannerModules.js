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

  return findings;
}

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
  const findings = analyzeFindings(collectors, { cookies, storage, dom, consent, topHeaders, performance });

  return {
    session: sessionLabel,
    artifacts: { collectors, cookies, storage, dom, consent, topHeaders, performance },
    findings
  };
}
