/**
 * Marketing Tag Agent - Detects and analyzes marketing/tracking tools
 */

import { BaseAgent } from '../core/BaseAgent.js';

const TOOL_PATTERNS = [
  {
    name: 'Google Analytics 4',
    category: 'analytics',
    hitRegex: /(www|region\d+)\.google-analytics\.com\/g\/collect/i,
    libRegex: /gtag\/js\?id=G-/i,
    domains: ['google-analytics.com', 'g.doubleclick.net']
  },
  {
    name: 'Google Analytics Universal',
    category: 'analytics',
    hitRegex: /google-analytics\.com\/collect(\?|$)/i,
    libRegex: /google-analytics\.com\/analytics\.js/i,
    domains: ['google-analytics.com']
  },
  {
    name: 'Google Tag Manager',
    category: 'tagmanager',
    libRegex: /googletagmanager\.com\/gtm\.js/i,
    domains: ['googletagmanager.com']
  },
  {
    name: 'Google Ads',
    category: 'ads',
    hitRegex: /(googleadservices|googlesyndication)\.com/i,
    domains: ['googleadservices.com', 'googlesyndication.com']
  },
  {
    name: 'Meta Pixel',
    category: 'ads',
    hitRegex: /facebook\.com\/tr/i,
    libRegex: /connect\.facebook\.net/i,
    domains: ['facebook.com', 'connect.facebook.net']
  },
  {
    name: 'TikTok Pixel',
    category: 'ads',
    hitRegex: /analytics\.tiktok\.com/i,
    domains: ['analytics.tiktok.com']
  },
  {
    name: 'Hotjar',
    category: 'ux',
    hitRegex: /(static|script)\.hotjar\.com/i,
    domains: ['static.hotjar.com', 'script.hotjar.com']
  },
  {
    name: 'LinkedIn Insight',
    category: 'ads',
    hitRegex: /(px\.ads\.linkedin\.com|snap\.licdn\.com)/i,
    domains: ['px.ads.linkedin.com', 'snap.licdn.com']
  }
];

export class MarketingTagAgent extends BaseAgent {
  constructor(options = {}) {
    super('marketing', {
      priority: 20,
      dependencies: [],
      timeout: 10000,
      maxRetries: 2,
      version: '1.0.0',
      ...options
    });

    this.toolPatterns = TOOL_PATTERNS;
    this.requestLog = [];
  }

  /**
   * Execute marketing tag detection
   * @param {import('../core/ScanContext.js').ScanContext} context
   * @returns {Promise<import('../types/index.js').AgentResult>}
   */
  async execute(context) {
    const startTime = Date.now();
    const findings = [];
    const page = context.page;

    try {
      // 1. Collect network requests
      this.log('info', 'Collecting network requests');
      this.requestLog = context.getMetadata('networkRequests') || [];

      // 2. Perform network-based detection
      this.log('info', 'Analyzing network traffic for marketing tools');
      const networkDetection = this.analyzeNetworkTraffic(this.requestLog);

      // 3. Perform DOM-based detection
      this.log('info', 'Scanning DOM for marketing tool scripts');
      const domDetection = await this.scanDOM(page);

      // 4. Combine detection results
      const detectedTools = this.combineDetections(networkDetection, domDetection);

      // 5. Create findings for each detected tool
      for (const tool of detectedTools) {
        findings.push(
          this.createFinding({
            type: 'marketing_tool_detected',
            severity: 'info',
            message: `${tool.name} detected`,
            evidence: {
              category: tool.category,
              detectionMethods: tool.detectedBy,
              networkHits: tool.networkHits,
              domPresence: tool.domPresent,
              scriptCount: tool.scriptCount,
              hitUrls: tool.hitUrls?.slice(0, 3) || []
            },
            toolName: tool.name,
            category: tool.category
          })
        );

        // Analyze tool compliance in current mode
        if (context.mode !== 'no-consent') {
          const compliance = this.analyzeToolCompliance(
            tool,
            context.mode,
            this.requestLog
          );

          findings.push(
            this.createFinding({
              type: 'tool_compliance',
              severity: compliance.severity,
              message: compliance.message,
              evidence: compliance.evidence,
              toolName: tool.name,
              category: tool.category
            })
          );
        }
      }

      // 6. Overall summary
      findings.push(
        this.createFinding({
          type: 'marketing_tools_summary',
          severity: 'info',
          message: `Found ${detectedTools.length} marketing/tracking tools`,
          evidence: {
            totalTools: detectedTools.length,
            byCategory: this.groupByCategory(detectedTools),
            consentMode: context.mode,
            networkRequestCount: this.requestLog.length
          }
        })
      );

      const duration = Date.now() - startTime;
      return this.createSuccessResult(findings, {
        duration,
        startTime: new Date(startTime),
        endTime: new Date(),
        toolsDetected: detectedTools.length,
        networkRequests: this.requestLog.length
      });
    } catch (error) {
      this.log('error', 'Marketing tag agent execution failed', { error: error.message });
      return this.createFailureResult(error, findings, {
        duration: Date.now() - startTime,
        startTime: new Date(startTime),
        endTime: new Date()
      });
    }
  }

  /**
   * Analyze network traffic for marketing tools
   * @param {Array} requests - Network request log
   * @returns {Object}
   */
  analyzeNetworkTraffic(requests) {
    const detected = {};

    for (const pattern of this.toolPatterns) {
      const hits = [];

      for (const req of requests) {
        const url = req.url || '';

        // Check hit regex
        if (pattern.hitRegex && pattern.hitRegex.test(url)) {
          hits.push({
            url,
            type: 'hit',
            status: req.status,
            timestamp: req.timestamp
          });
        }

        // Check lib regex
        if (pattern.libRegex && pattern.libRegex.test(url)) {
          hits.push({
            url,
            type: 'library',
            status: req.status,
            timestamp: req.timestamp
          });
        }
      }

      if (hits.length > 0) {
        detected[pattern.name] = {
          name: pattern.name,
          category: pattern.category,
          hits,
          detectedBy: ['network']
        };
      }
    }

    return detected;
  }

  /**
   * Scan DOM for marketing tool presence
   * @param {Object} page - Playwright page
   * @returns {Promise<Object>}
   */
  async scanDOM(page) {
    return await page.evaluate((patterns) => {
      const detected = {};

      const scripts = Array.from(document.scripts || []);
      const iframes = Array.from(document.querySelectorAll('iframe'));

      for (const pattern of patterns) {
        const matchingScripts = scripts.filter(s =>
          s.src && (
            (pattern.libRegex && new RegExp(pattern.libRegex).test(s.src)) ||
            pattern.domains?.some(d => s.src.includes(d))
          )
        );

        const matchingIframes = iframes.filter(f =>
          f.src && pattern.domains?.some(d => f.src.includes(d))
        );

        if (matchingScripts.length > 0 || matchingIframes.length > 0) {
          detected[pattern.name] = {
            name: pattern.name,
            category: pattern.category,
            scriptCount: matchingScripts.length,
            iframeCount: matchingIframes.length,
            scripts: matchingScripts.map(s => ({ src: s.src, async: s.async, defer: s.defer })),
            detectedBy: ['dom']
          };
        }

        // Check window globals
        if (pattern.name === 'Google Analytics 4' && typeof window.gtag === 'function') {
          detected[pattern.name] = detected[pattern.name] || {
            name: pattern.name,
            category: pattern.category,
            detectedBy: []
          };
          detected[pattern.name].windowGlobal = 'gtag';
          if (!detected[pattern.name].detectedBy.includes('dom')) {
            detected[pattern.name].detectedBy.push('dom');
          }
        }

        if (pattern.name === 'Google Analytics Universal' && typeof window.ga === 'function') {
          detected[pattern.name] = detected[pattern.name] || {
            name: pattern.name,
            category: pattern.category,
            detectedBy: []
          };
          detected[pattern.name].windowGlobal = 'ga';
          if (!detected[pattern.name].detectedBy.includes('dom')) {
            detected[pattern.name].detectedBy.push('dom');
          }
        }

        if (pattern.name === 'Meta Pixel' && typeof window.fbq === 'function') {
          detected[pattern.name] = detected[pattern.name] || {
            name: pattern.name,
            category: pattern.category,
            detectedBy: []
          };
          detected[pattern.name].windowGlobal = 'fbq';
          if (!detected[pattern.name].detectedBy.includes('dom')) {
            detected[pattern.name].detectedBy.push('dom');
          }
        }

        if (pattern.name === 'Hotjar' && typeof window.hj === 'function') {
          detected[pattern.name] = detected[pattern.name] || {
            name: pattern.name,
            category: pattern.category,
            detectedBy: []
          };
          detected[pattern.name].windowGlobal = 'hj';
          if (!detected[pattern.name].detectedBy.includes('dom')) {
            detected[pattern.name].detectedBy.push('dom');
          }
        }
      }

      return detected;
    }, this.toolPatterns.map(p => ({
      name: p.name,
      category: p.category,
      libRegex: p.libRegex?.source,
      domains: p.domains
    })));
  }

  /**
   * Combine network and DOM detection results
   * @param {Object} networkDetection
   * @param {Object} domDetection
   * @returns {Array}
   */
  combineDetections(networkDetection, domDetection) {
    const combined = {};

    // Add network detections
    for (const [name, data] of Object.entries(networkDetection)) {
      combined[name] = {
        ...data,
        networkHits: data.hits.length,
        hitUrls: data.hits.map(h => h.url),
        domPresent: false,
        scriptCount: 0
      };
    }

    // Merge DOM detections
    for (const [name, data] of Object.entries(domDetection)) {
      if (combined[name]) {
        combined[name].domPresent = true;
        combined[name].scriptCount = data.scriptCount || 0;
        combined[name].detectedBy = [
          ...new Set([...combined[name].detectedBy, ...data.detectedBy])
        ];
      } else {
        combined[name] = {
          ...data,
          networkHits: 0,
          hitUrls: [],
          domPresent: true,
          scriptCount: data.scriptCount || 0
        };
      }
    }

    return Object.values(combined);
  }

  /**
   * Analyze tool compliance in current consent mode
   * @param {Object} tool - Detected tool
   * @param {string} mode - Consent mode
   * @param {Array} requests - Network requests
   * @returns {Object}
   */
  analyzeToolCompliance(tool, mode, requests) {
    const hasNetworkActivity = tool.networkHits > 0;

    if (mode === 'reject' && hasNetworkActivity) {
      return {
        severity: 'high',
        message: `${tool.name} sends data despite consent rejection`,
        evidence: {
          consentMode: mode,
          networkHits: tool.networkHits,
          compliance: 'non-compliant',
          gdprRisk: 'high'
        }
      };
    }

    if (mode === 'accept' && hasNetworkActivity) {
      return {
        severity: 'info',
        message: `${tool.name} correctly sends data after consent`,
        evidence: {
          consentMode: mode,
          networkHits: tool.networkHits,
          compliance: 'compliant',
          gdprRisk: 'none'
        }
      };
    }

    if (mode === 'accept' && !hasNetworkActivity && tool.domPresent) {
      return {
        severity: 'medium',
        message: `${tool.name} present but not sending data`,
        evidence: {
          consentMode: mode,
          networkHits: 0,
          compliance: 'misconfigured',
          gdprRisk: 'low'
        }
      };
    }

    return {
      severity: 'info',
      message: `${tool.name} behavior normal for ${mode} mode`,
      evidence: {
        consentMode: mode,
        networkHits: tool.networkHits,
        compliance: 'unknown',
        gdprRisk: 'unknown'
      }
    };
  }

  /**
   * Group tools by category
   * @param {Array} tools - Detected tools
   * @returns {Object}
   */
  groupByCategory(tools) {
    const grouped = {};
    for (const tool of tools) {
      if (!grouped[tool.category]) {
        grouped[tool.category] = [];
      }
      grouped[tool.category].push(tool.name);
    }
    return grouped;
  }

  /**
   * Prepare agent before execution
   * @param {import('../core/ScanContext.js').ScanContext} context
   */
  async prepare(context) {
    // Attach network listener if not already attached
    if (!context.hasMetadata('networkListenerAttached')) {
      const page = context.page;
      const requests = [];

      page.on('requestfinished', async (request) => {
        try {
          const response = await request.response();
          requests.push({
            url: request.url(),
            method: request.method(),
            status: response ? response.status() : 0,
            resourceType: request.resourceType(),
            timestamp: new Date()
          });
        } catch (e) {
          // Ignore errors
        }
      });

      // Store in context metadata
      return context.withMetadata('networkRequests', requests)
        .withMetadata('networkListenerAttached', true);
    }
  }

  /**
   * Get current session identifier
   * @returns {string}
   */
  getCurrentSession() {
    return 'marketing-scan';
  }
}
