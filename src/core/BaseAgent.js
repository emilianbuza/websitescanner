/**
 * Base class for all scanner agents
 * Provides common functionality and enforces interface
 */
export class BaseAgent {
  /**
   * @param {string} name - Agent name
   * @param {Object} options - Agent options
   * @param {number} [options.priority] - Execution priority (lower = earlier)
   * @param {string[]} [options.dependencies] - Names of dependent agents
   * @param {number} [options.timeout] - Execution timeout in ms
   * @param {number} [options.maxRetries] - Maximum retry attempts
   * @param {string} [options.version] - Agent version
   */
  constructor(name, options = {}) {
    this.name = name;
    this.priority = options.priority ?? 100;
    this.dependencies = options.dependencies ?? [];
    this.timeout = options.timeout ?? 30000;
    this.maxRetries = options.maxRetries ?? 2;
    this.version = options.version ?? '1.0.0';
    this.enabled = true;
  }

  /**
   * Execute the agent (must be implemented by subclass)
   * @param {import('./ScanContext.js').ScanContext} context
   * @returns {Promise<import('../types/index.js').AgentResult>}
   * @throws {Error} If not implemented
   */
  async execute(context) {
    throw new Error(`Agent ${this.name} must implement execute() method`);
  }

  /**
   * Validate if agent can run with given context
   * @param {import('./ScanContext.js').ScanContext} context
   * @returns {boolean}
   */
  validate(context) {
    return context && context.url && context.page !== null;
  }

  /**
   * Prepare agent before execution
   * @param {import('./ScanContext.js').ScanContext} context
   * @returns {Promise<void>}
   */
  async prepare(context) {
    // Override in subclass if needed
  }

  /**
   * Cleanup after execution
   * @param {import('./ScanContext.js').ScanContext} context
   * @returns {Promise<void>}
   */
  async cleanup(context) {
    // Override in subclass if needed
  }

  /**
   * Create a successful result
   * @param {import('../types/index.js').Finding[]} findings
   * @param {Object} metadata
   * @returns {import('../types/index.js').AgentResult}
   */
  createSuccessResult(findings, metadata = {}) {
    return {
      agentName: this.name,
      success: true,
      findings: findings || [],
      metadata: {
        ...metadata,
        version: this.version
      },
      errors: []
    };
  }

  /**
   * Create a failure result
   * @param {Error} error
   * @param {import('../types/index.js').Finding[]} findings - Partial findings before failure
   * @param {Object} metadata
   * @returns {import('../types/index.js').AgentResult}
   */
  createFailureResult(error, findings = [], metadata = {}) {
    return {
      agentName: this.name,
      success: false,
      findings,
      metadata: {
        ...metadata,
        version: this.version
      },
      errors: [{
        message: error.message,
        code: error.code || 'AGENT_ERROR',
        stack: error.stack,
        recoverable: error.recoverable ?? false,
        timestamp: new Date()
      }]
    };
  }

  /**
   * Create a finding
   * @param {Object} params
   * @param {string} params.type
   * @param {import('../types/index.js').Severity} params.severity
   * @param {string} params.message
   * @param {Object} [params.evidence]
   * @param {string} [params.category]
   * @param {string} [params.toolName]
   * @returns {import('../types/index.js').Finding}
   */
  createFinding({ type, severity, message, evidence = {}, category = null, toolName = null }) {
    return {
      type,
      severity,
      session: this.getCurrentSession(),
      message,
      evidence,
      source: this.name,
      toolName,
      category,
      timestamp: new Date()
    };
  }

  /**
   * Get current session identifier
   * @returns {string}
   */
  getCurrentSession() {
    // Override in subclass or get from context
    return 'default';
  }

  /**
   * Log message (can be overridden for custom logging)
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {Object} [data] - Additional data
   */
  log(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${this.name}] [${level.toUpperCase()}] ${message}`, data);
  }

  /**
   * Measure execution time
   * @param {Function} fn - Function to measure
   * @returns {Promise<{result: any, duration: number}>}
   */
  async measure(fn) {
    const startTime = Date.now();
    const result = await fn();
    const duration = Date.now() - startTime;
    return { result, duration };
  }

  /**
   * Execute with retry logic
   * @param {Function} fn - Function to execute
   * @param {number} [maxRetries] - Override max retries
   * @returns {Promise<any>}
   */
  async withRetry(fn, maxRetries = this.maxRetries) {
    let lastError;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        if (attempt < maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 5000); // Exponential backoff
          this.log('warn', `Attempt ${attempt + 1} failed, retrying in ${delay}ms`, { error: error.message });
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    throw lastError;
  }

  /**
   * Execute with timeout
   * @param {Function} fn - Function to execute
   * @param {number} [timeout] - Override timeout
   * @returns {Promise<any>}
   */
  async withTimeout(fn, timeout = this.timeout) {
    return Promise.race([
      fn(),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Agent ${this.name} timeout after ${timeout}ms`)), timeout)
      )
    ]);
  }

  /**
   * Check if agent is enabled
   * @returns {boolean}
   */
  isEnabled() {
    return this.enabled;
  }

  /**
   * Enable agent
   */
  enable() {
    this.enabled = true;
  }

  /**
   * Disable agent
   */
  disable() {
    this.enabled = false;
  }

  /**
   * Get agent info
   * @returns {Object}
   */
  getInfo() {
    return {
      name: this.name,
      version: this.version,
      priority: this.priority,
      dependencies: this.dependencies,
      enabled: this.enabled,
      timeout: this.timeout,
      maxRetries: this.maxRetries
    };
  }
}
