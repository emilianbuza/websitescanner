/**
 * Orchestrates the execution of multiple agents for website scanning
 * Handles dependency resolution, parallel execution, and result aggregation
 */

import { ScanContext } from './ScanContext.js';
import { EventBus } from '../infrastructure/EventBus.js';
import { ErrorHandler, ScanError, ErrorCategory, ErrorSeverity } from '../infrastructure/ErrorHandler.js';
import { chromium } from 'playwright';

export class ScanOrchestrator {
  /**
   * @param {Object} options
   * @param {Array} [options.agents] - Array of agent instances
   * @param {EventBus} [options.eventBus] - Event bus instance
   * @param {ErrorHandler} [options.errorHandler] - Error handler instance
   */
  constructor(options = {}) {
    this.agents = options.agents || [];
    this.eventBus = options.eventBus || new EventBus();
    this.errorHandler = options.errorHandler || new ErrorHandler(this.eventBus);
    this.scanId = null;
  }

  /**
   * Execute a complete scan
   * @param {string} url - URL to scan
   * @param {import('../types/index.js').ScanConfig} [config] - Scan configuration
   * @returns {Promise<import('../types/index.js').ScanResult>}
   */
  async executeScan(url, config) {
    this.scanId = this.generateScanId();
    const startTime = Date.now();

    try {
      // Emit scan started event
      await this.eventBus.emit('scan:started', { url, scanId: this.scanId });
      await this.eventBus.emitProgress('initialization', 0, 'Initializing scan...');

      // Create initial context
      const baseContext = new ScanContext({ url, mode: 'no-consent', config });

      // Validate URL
      const validation = baseContext.validate();
      if (!validation.valid) {
        throw new ScanError(`Invalid scan parameters: ${validation.errors.join(', ')}`, {
          code: 'INVALID_PARAMETERS',
          category: ErrorCategory.VALIDATION,
          severity: ErrorSeverity.FATAL,
          recoverable: false
        });
      }

      // Launch browser
      await this.eventBus.emitProgress('browser', 10, 'Launching browser...');
      const { browser, browserContext, page } = await this.launchBrowser(config);

      try {
        // Create context with browser
        const contextWithBrowser = baseContext.withBrowser(browser, browserContext, page);

        // Run agents in all three consent modes
        const modes = ['no-consent', 'accept', 'reject'];
        const allResults = [];

        for (let i = 0; i < modes.length; i++) {
          const mode = modes[i];
          const modeContext = contextWithBrowser.withMode(mode);

          const progressBase = 10 + (i * 25);
          await this.eventBus.emitProgress(
            `scan-${mode}`,
            progressBase,
            `Scanning in ${mode} mode...`
          );

          // Navigate to page
          await this.navigateToPage(page, url, mode, config);

          // Execute agents
          const modeResults = await this.executeAgents(modeContext, progressBase, 25);
          allResults.push(...modeResults);
        }

        // Aggregate results
        await this.eventBus.emitProgress('aggregation', 90, 'Aggregating results...');
        const scanResult = this.aggregateResults(url, allResults, startTime);

        // Emit scan completed event
        await this.eventBus.emit('scan:completed', {
          scanId: this.scanId,
          url,
          duration: Date.now() - startTime,
          findingCount: scanResult.allFindings.length
        });
        await this.eventBus.emitProgress('completed', 100, 'Scan completed!');

        return scanResult;
      } finally {
        // Always close browser
        if (browser) {
          await browser.close().catch(err =>
            console.error('Error closing browser:', err)
          );
        }
      }
    } catch (error) {
      const scanError = this.errorHandler.handle(error, { url, scanId: this.scanId });

      await this.eventBus.emit('scan:failed', {
        scanId: this.scanId,
        url,
        error: scanError.toJSON()
      });

      throw scanError;
    }
  }

  /**
   * Launch browser with configuration
   * @param {import('../types/index.js').ScanConfig} config
   * @returns {Promise<{browser: Object, browserContext: Object, page: Object}>}
   */
  async launchBrowser(config) {
    return this.errorHandler.withRetry(
      async () => {
        const launchOptions = {
          headless: config.headless ?? true,
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor'
          ]
        };

        const browser = await chromium.launch(launchOptions);
        const browserContext = await browser.newContext({
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          viewport: { width: 1920, height: 1080 },
          ignoreHTTPSErrors: true
        });

        const page = await browserContext.newPage();

        return { browser, browserContext, page };
      },
      { category: ErrorCategory.BROWSER }
    );
  }

  /**
   * Navigate to page with consent handling
   * @param {Object} page - Playwright page
   * @param {string} url - Target URL
   * @param {string} mode - Consent mode
   * @param {import('../types/index.js').ScanConfig} config
   */
  async navigateToPage(page, url, mode, config) {
    return this.errorHandler.withRetry(
      async () => {
        await page.goto(url, {
          waitUntil: 'domcontentloaded',
          timeout: config.timeout || 25000
        });

        // Handle consent based on mode
        if (mode === 'accept' || mode === 'reject') {
          await this.handleConsent(page, mode, config);
        }

        // Wait for page to stabilize
        await Promise.race([
          page.waitForLoadState('networkidle', { timeout: 4000 }).catch(() => {}),
          page.waitForTimeout(2000)
        ]);
      },
      { category: ErrorCategory.NETWORK }
    );
  }

  /**
   * Handle consent banner
   * @param {Object} page - Playwright page
   * @param {string} action - 'accept' or 'reject'
   * @param {import('../types/index.js').ScanConfig} config
   */
  async handleConsent(page, action, config) {
    try {
      await page.waitForTimeout(1800);

      const patterns = action === 'accept'
        ? config.agentConfigs?.consent?.acceptPatterns || [/accept|zustimmen|einverstanden/i]
        : config.agentConfigs?.consent?.rejectPatterns || [/reject|ablehnen|nur.*notwendig/i];

      const selectors = [
        'button',
        '[role="button"]',
        'input[type="button"]',
        'a[href]',
        '[onclick]',
        'div[role="button"]',
        'span[role="button"]'
      ];

      const elements = await page.$$(selectors.join(','));

      for (const el of elements) {
        const text = (await el.textContent())?.toLowerCase() || '';
        const aria = (await el.getAttribute('aria-label'))?.toLowerCase() || '';
        const cls = (await el.getAttribute('class'))?.toLowerCase() || '';
        const id = (await el.getAttribute('id'))?.toLowerCase() || '';
        const haystack = `${text} ${aria} ${cls} ${id}`;

        const isVisible = await el.isVisible().catch(() => false);
        if (!isVisible) continue;

        if (patterns.some(pattern => pattern.test(haystack))) {
          await el.click({ delay: 10 });
          await page.waitForTimeout(config.waitAfterConsent || 1500);
          return true;
        }
      }

      return false;
    } catch (error) {
      console.warn(`Consent handling failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Execute all agents with dependency resolution
   * @param {ScanContext} context
   * @param {number} progressBase - Base progress percentage
   * @param {number} progressRange - Progress range for this phase
   * @returns {Promise<Array>}
   */
  async executeAgents(context, progressBase, progressRange) {
    // Filter enabled agents
    const enabledAgents = this.agents.filter(agent =>
      agent.isEnabled() &&
      agent.validate(context) &&
      context.config.enabledAgents.includes(agent.name)
    );

    if (enabledAgents.length === 0) {
      return [];
    }

    // Resolve dependencies and create execution groups
    const executionGroups = this.resolveDependencies(enabledAgents);
    const results = [];

    // Execute each group (groups can run in parallel)
    let completedAgents = 0;
    const totalAgents = enabledAgents.length;

    for (const group of executionGroups) {
      // Execute agents in group in parallel
      const groupResults = await Promise.all(
        group.map(agent => this.executeAgent(agent, context))
      );

      results.push(...groupResults);

      // Update progress
      completedAgents += group.length;
      const progress = progressBase + (completedAgents / totalAgents) * progressRange;
      await this.eventBus.emitProgress(
        `agents-${context.mode}`,
        Math.round(progress),
        `Completed ${completedAgents}/${totalAgents} agents in ${context.mode} mode`
      );
    }

    return results;
  }

  /**
   * Execute a single agent
   * @param {Object} agent - Agent instance
   * @param {ScanContext} context
   * @returns {Promise<import('../types/index.js').AgentResult>}
   */
  async executeAgent(agent, context) {
    const startTime = Date.now();

    try {
      // Emit agent started event
      await this.eventBus.emitAgentStarted(agent.name, { mode: context.mode });

      // Prepare agent
      await agent.prepare(context);

      // Execute with timeout and retry
      const result = await this.errorHandler.withRetry(
        async () => {
          return await this.errorHandler.withTimeout(
            () => agent.execute(context),
            agent.timeout
          );
        },
        {
          category: ErrorCategory.AGENT,
          maxRetries: agent.maxRetries,
          onRetry: async (error, attempt, delay) => {
            console.log(
              `Agent ${agent.name} failed (attempt ${attempt + 1}/${agent.maxRetries}), ` +
              `retrying in ${delay}ms: ${error.message}`
            );
          }
        }
      );

      // Add duration to result
      result.metadata.duration = Date.now() - startTime;
      result.metadata.startTime = new Date(startTime);
      result.metadata.endTime = new Date();

      // Cleanup agent
      await agent.cleanup(context);

      // Emit agent completed event
      await this.eventBus.emitAgentCompleted(agent.name, result);

      return result;
    } catch (error) {
      const duration = Date.now() - startTime;
      const scanError = this.errorHandler.handle(error, {
        agentName: agent.name,
        mode: context.mode
      });

      // Return failure result
      const failureResult = agent.createFailureResult(scanError, [], {
        duration,
        startTime: new Date(startTime),
        endTime: new Date()
      });

      await this.eventBus.emitAgentCompleted(agent.name, failureResult);

      return failureResult;
    }
  }

  /**
   * Resolve agent dependencies and create execution groups
   * @param {Array} agents - Array of agents
   * @returns {Array<Array>} Groups of agents that can run in parallel
   */
  resolveDependencies(agents) {
    const groups = [];
    const completed = new Set();
    const remaining = [...agents];

    while (remaining.length > 0) {
      // Find agents with no unmet dependencies
      const ready = remaining.filter(agent =>
        agent.dependencies.every(dep => completed.has(dep))
      );

      if (ready.length === 0) {
        // Circular dependency or invalid dependency
        throw new ScanError('Circular or invalid agent dependencies detected', {
          code: 'DEPENDENCY_ERROR',
          category: ErrorCategory.CONFIGURATION,
          severity: ErrorSeverity.FATAL,
          context: {
            remaining: remaining.map(a => ({
              name: a.name,
              dependencies: a.dependencies
            }))
          }
        });
      }

      // Sort by priority
      ready.sort((a, b) => a.priority - b.priority);

      groups.push(ready);

      // Mark as completed
      ready.forEach(agent => completed.add(agent.name));

      // Remove from remaining
      remaining.splice(0, remaining.length, ...remaining.filter(a => !ready.includes(a)));
    }

    return groups;
  }

  /**
   * Aggregate results from all agents
   * @param {string} url - Scanned URL
   * @param {Array} agentResults - Results from all agents
   * @param {number} startTime - Scan start time
   * @returns {import('../types/index.js').ScanResult}
   */
  aggregateResults(url, agentResults, startTime) {
    const allFindings = agentResults.flatMap(result => result.findings);

    // Calculate summary statistics
    const summary = {
      totalFindings: allFindings.length,
      criticalFindings: allFindings.filter(f => f.severity === 'critical').length,
      highFindings: allFindings.filter(f => f.severity === 'high').length,
      mediumFindings: allFindings.filter(f => f.severity === 'medium').length,
      lowFindings: allFindings.filter(f => f.severity === 'low').length,
      infoFindings: allFindings.filter(f => f.severity === 'info').length,
      successfulAgents: agentResults.filter(r => r.success).length,
      failedAgents: agentResults.filter(r => !r.success).length,
      totalAgentErrors: agentResults.reduce((sum, r) => sum + r.errors.length, 0)
    };

    // Calculate compliance score
    const score = this.calculateScore(summary, allFindings);

    return {
      scanId: this.scanId,
      url,
      timestamp: new Date(),
      agentResults,
      allFindings,
      summary,
      score,
      duration: Date.now() - startTime
    };
  }

  /**
   * Calculate compliance score (0-100)
   * @param {Object} summary - Summary statistics
   * @param {Array} findings - All findings
   * @returns {number}
   */
  calculateScore(summary, findings) {
    let score = 100;

    // Deduct for critical/high severity findings
    score -= summary.criticalFindings * 20;
    score -= summary.highFindings * 10;
    score -= summary.mediumFindings * 5;
    score -= summary.lowFindings * 1;

    // Deduct for failed agents
    score -= summary.failedAgents * 10;

    // Bonus for having info findings (shows thorough scan)
    score += Math.min(summary.infoFindings * 0.5, 10);

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  /**
   * Generate unique scan ID
   * @returns {string}
   */
  generateScanId() {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Register an agent
   * @param {Object} agent - Agent instance
   */
  registerAgent(agent) {
    if (!agent.name) {
      throw new Error('Agent must have a name');
    }

    // Check for duplicate
    if (this.agents.find(a => a.name === agent.name)) {
      throw new Error(`Agent with name ${agent.name} already registered`);
    }

    this.agents.push(agent);
  }

  /**
   * Unregister an agent
   * @param {string} agentName - Agent name
   */
  unregisterAgent(agentName) {
    const index = this.agents.findIndex(a => a.name === agentName);
    if (index !== -1) {
      this.agents.splice(index, 1);
    }
  }

  /**
   * Get registered agents
   * @returns {Array}
   */
  getAgents() {
    return this.agents.map(agent => agent.getInfo());
  }
}
