/**
 * Immutable scan context that holds all state for a scan operation
 * Prevents state mutation and ensures thread safety
 */
export class ScanContext {
  /**
   * @param {Object} params
   * @param {string} params.url - Target URL
   * @param {import('../types/index.js').ConsentMode} params.mode - Consent mode
   * @param {import('../types/index.js').ScanConfig} params.config - Configuration
   * @param {Object} [params.browser] - Playwright browser
   * @param {Object} [params.context] - Playwright context
   * @param {Object} [params.page] - Playwright page
   * @param {Map<string, any>} [params.metadata] - Additional metadata
   */
  constructor({ url, mode, config, browser = null, context = null, page = null, metadata = new Map() }) {
    // Make all properties read-only
    Object.defineProperty(this, 'url', { value: url, writable: false, enumerable: true });
    Object.defineProperty(this, 'mode', { value: mode, writable: false, enumerable: true });
    Object.defineProperty(this, 'config', { value: Object.freeze({ ...config }), writable: false, enumerable: true });
    Object.defineProperty(this, 'browser', { value: browser, writable: false, enumerable: true });
    Object.defineProperty(this, 'context', { value: context, writable: false, enumerable: true });
    Object.defineProperty(this, 'page', { value: page, writable: false, enumerable: true });
    Object.defineProperty(this, 'metadata', { value: new Map(metadata), writable: false, enumerable: true });

    // Freeze the object to prevent any modifications
    Object.freeze(this);
  }

  /**
   * Create a new context with different mode
   * @param {import('../types/index.js').ConsentMode} mode
   * @returns {ScanContext}
   */
  withMode(mode) {
    return new ScanContext({
      url: this.url,
      mode,
      config: this.config,
      browser: this.browser,
      context: this.context,
      page: this.page,
      metadata: this.metadata
    });
  }

  /**
   * Create a new context with browser instances
   * @param {Object} browser - Playwright browser
   * @param {Object} context - Playwright context
   * @param {Object} page - Playwright page
   * @returns {ScanContext}
   */
  withBrowser(browser, context, page) {
    return new ScanContext({
      url: this.url,
      mode: this.mode,
      config: this.config,
      browser,
      context,
      page,
      metadata: this.metadata
    });
  }

  /**
   * Create a new context with additional metadata
   * @param {string} key - Metadata key
   * @param {any} value - Metadata value
   * @returns {ScanContext}
   */
  withMetadata(key, value) {
    const newMetadata = new Map(this.metadata);
    newMetadata.set(key, value);
    return new ScanContext({
      url: this.url,
      mode: this.mode,
      config: this.config,
      browser: this.browser,
      context: this.context,
      page: this.page,
      metadata: newMetadata
    });
  }

  /**
   * Get metadata value
   * @param {string} key
   * @returns {any}
   */
  getMetadata(key) {
    return this.metadata.get(key);
  }

  /**
   * Check if metadata exists
   * @param {string} key
   * @returns {boolean}
   */
  hasMetadata(key) {
    return this.metadata.has(key);
  }

  /**
   * Validate context before use
   * @returns {{valid: boolean, errors: string[]}}
   */
  validate() {
    const errors = [];

    if (!this.url) {
      errors.push('URL is required');
    }

    if (!this.mode) {
      errors.push('Consent mode is required');
    }

    if (!this.config) {
      errors.push('Config is required');
    }

    try {
      new URL(this.url);
    } catch (e) {
      errors.push(`Invalid URL: ${e.message}`);
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Convert to plain object for serialization
   * @returns {Object}
   */
  toJSON() {
    return {
      url: this.url,
      mode: this.mode,
      config: this.config,
      metadata: Object.fromEntries(this.metadata),
      hasBrowser: !!this.browser,
      hasContext: !!this.context,
      hasPage: !!this.page
    };
  }
}

/**
 * Create default scan config
 * @returns {import('../types/index.js').ScanConfig}
 */
export function createDefaultConfig() {
  return {
    timeout: 25000,
    waitAfterConsent: 1500,
    maxRetries: 2,
    headless: true,
    enabledAgents: ['consent', 'marketing', 'security', 'performance', 'cookie'],
    agentConfigs: {
      consent: {
        acceptPatterns: [/accept|zustimmen|einverstanden|alle.*(zulassen|akzeptieren)|ok|verstanden|allow.*all/i],
        rejectPatterns: [/reject|ablehnen|nur.*(notwendig|necessary|minimal)|essential.*only|necessary.*only/i]
      },
      marketing: {
        timeout: 5000,
        deepScan: true
      },
      security: {
        checkHeaders: true,
        checkMixedContent: true,
        checkVulnerabilities: true
      },
      performance: {
        slowThreshold: 500,
        collectResourceTimings: true
      },
      cookie: {
        trackChanges: true,
        validateGDPR: true
      }
    }
  };
}
