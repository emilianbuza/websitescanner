/**
 * Centralized error handling with categorization and recovery strategies
 */

/**
 * Error categories
 */
export const ErrorCategory = {
  NETWORK: 'network',
  BROWSER: 'browser',
  VALIDATION: 'validation',
  TIMEOUT: 'timeout',
  AGENT: 'agent',
  DATABASE: 'database',
  CONFIGURATION: 'configuration',
  UNKNOWN: 'unknown'
};

/**
 * Error severity levels
 */
export const ErrorSeverity = {
  FATAL: 'fatal',       // Cannot continue scanning
  ERROR: 'error',       // Agent failed, but scan can continue
  WARNING: 'warning',   // Issue detected, but not critical
  INFO: 'info'          // Informational
};

/**
 * Custom error class with metadata
 */
export class ScanError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = 'ScanError';
    this.code = options.code || 'SCAN_ERROR';
    this.category = options.category || ErrorCategory.UNKNOWN;
    this.severity = options.severity || ErrorSeverity.ERROR;
    this.recoverable = options.recoverable ?? true;
    this.context = options.context || {};
    this.timestamp = new Date();
    this.originalError = options.originalError || null;

    // Capture stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ScanError);
    }
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      category: this.category,
      severity: this.severity,
      recoverable: this.recoverable,
      context: this.context,
      timestamp: this.timestamp,
      stack: this.stack
    };
  }
}

/**
 * Error handler with retry logic and recovery strategies
 */
export class ErrorHandler {
  constructor(eventBus) {
    this.eventBus = eventBus;
    this.errorLog = [];
    this.maxLogSize = 1000;
    this.retryStrategies = new Map();

    // Register default retry strategies
    this.registerDefaultStrategies();
  }

  /**
   * Register default retry strategies
   */
  registerDefaultStrategies() {
    // Network errors: retry with exponential backoff
    this.registerRetryStrategy(ErrorCategory.NETWORK, {
      maxRetries: 3,
      backoff: 'exponential',
      initialDelay: 1000,
      maxDelay: 5000
    });

    // Browser errors: retry with constant delay
    this.registerRetryStrategy(ErrorCategory.BROWSER, {
      maxRetries: 2,
      backoff: 'constant',
      initialDelay: 2000
    });

    // Timeout errors: retry once with increased timeout
    this.registerRetryStrategy(ErrorCategory.TIMEOUT, {
      maxRetries: 1,
      backoff: 'constant',
      initialDelay: 0,
      increaseTimeout: true
    });

    // Validation errors: don't retry
    this.registerRetryStrategy(ErrorCategory.VALIDATION, {
      maxRetries: 0
    });
  }

  /**
   * Register custom retry strategy
   * @param {string} category - Error category
   * @param {Object} strategy - Retry strategy
   */
  registerRetryStrategy(category, strategy) {
    this.retryStrategies.set(category, strategy);
  }

  /**
   * Handle an error
   * @param {Error} error - Error object
   * @param {Object} [context] - Error context
   * @returns {ScanError}
   */
  handle(error, context = {}) {
    // Convert to ScanError if needed
    const scanError = error instanceof ScanError
      ? error
      : this.categorizeError(error, context);

    // Log error
    this.logError(scanError);

    // Emit error event
    if (this.eventBus) {
      this.eventBus.emitError(scanError, context).catch(err => {
        console.error('Failed to emit error event:', err);
      });
    }

    // Return enriched error
    return scanError;
  }

  /**
   * Categorize error based on message and type
   * @param {Error} error - Original error
   * @param {Object} context - Error context
   * @returns {ScanError}
   */
  categorizeError(error, context = {}) {
    const message = error.message || String(error);

    // Network errors
    if (/network|fetch|ECONNREFUSED|ETIMEDOUT|DNS/i.test(message)) {
      return new ScanError(message, {
        code: 'NETWORK_ERROR',
        category: ErrorCategory.NETWORK,
        severity: ErrorSeverity.WARNING,
        recoverable: true,
        context,
        originalError: error
      });
    }

    // Browser errors
    if (/browser|page|context|chromium|playwright/i.test(message)) {
      return new ScanError(message, {
        code: 'BROWSER_ERROR',
        category: ErrorCategory.BROWSER,
        severity: ErrorSeverity.ERROR,
        recoverable: true,
        context,
        originalError: error
      });
    }

    // Timeout errors
    if (/timeout|timed out/i.test(message)) {
      return new ScanError(message, {
        code: 'TIMEOUT_ERROR',
        category: ErrorCategory.TIMEOUT,
        severity: ErrorSeverity.WARNING,
        recoverable: true,
        context,
        originalError: error
      });
    }

    // Validation errors
    if (/invalid|validation|required/i.test(message)) {
      return new ScanError(message, {
        code: 'VALIDATION_ERROR',
        category: ErrorCategory.VALIDATION,
        severity: ErrorSeverity.ERROR,
        recoverable: false,
        context,
        originalError: error
      });
    }

    // Database errors
    if (/database|sqlite|sql/i.test(message)) {
      return new ScanError(message, {
        code: 'DATABASE_ERROR',
        category: ErrorCategory.DATABASE,
        severity: ErrorSeverity.ERROR,
        recoverable: true,
        context,
        originalError: error
      });
    }

    // Unknown error
    return new ScanError(message, {
      code: 'UNKNOWN_ERROR',
      category: ErrorCategory.UNKNOWN,
      severity: ErrorSeverity.ERROR,
      recoverable: true,
      context,
      originalError: error
    });
  }

  /**
   * Execute function with retry logic
   * @param {Function} fn - Function to execute
   * @param {Object} [options] - Retry options
   * @param {string} [options.category] - Error category for retry strategy
   * @param {number} [options.maxRetries] - Override max retries
   * @param {Function} [options.onRetry] - Callback on retry
   * @returns {Promise<any>}
   */
  async withRetry(fn, options = {}) {
    const category = options.category || ErrorCategory.UNKNOWN;
    const strategy = this.retryStrategies.get(category) || { maxRetries: 2, backoff: 'constant', initialDelay: 1000 };
    const maxRetries = options.maxRetries ?? strategy.maxRetries;

    let lastError;
    let currentTimeout = options.timeout;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        // Execute function with timeout if specified
        if (currentTimeout) {
          return await this.withTimeout(fn, currentTimeout);
        }
        return await fn();
      } catch (error) {
        lastError = this.handle(error, { attempt, maxRetries, category });

        if (attempt < maxRetries && lastError.recoverable) {
          // Calculate delay
          const delay = this.calculateDelay(strategy, attempt);

          // Increase timeout if strategy requires it
          if (strategy.increaseTimeout && currentTimeout) {
            currentTimeout = Math.min(currentTimeout * 1.5, 60000);
          }

          // Call onRetry callback
          if (options.onRetry) {
            await options.onRetry(lastError, attempt, delay);
          }

          // Wait before retry
          if (delay > 0) {
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        } else {
          break;
        }
      }
    }

    throw lastError;
  }

  /**
   * Calculate retry delay based on strategy
   * @param {Object} strategy - Retry strategy
   * @param {number} attempt - Current attempt number
   * @returns {number} Delay in ms
   */
  calculateDelay(strategy, attempt) {
    if (strategy.backoff === 'exponential') {
      const delay = strategy.initialDelay * Math.pow(2, attempt);
      return Math.min(delay, strategy.maxDelay || 30000);
    }
    return strategy.initialDelay || 1000;
  }

  /**
   * Execute function with timeout
   * @param {Function} fn - Function to execute
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<any>}
   */
  async withTimeout(fn, timeout) {
    return Promise.race([
      fn(),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Operation timeout after ${timeout}ms`)), timeout)
      )
    ]);
  }

  /**
   * Log error to internal log
   * @param {ScanError} error - Error to log
   */
  logError(error) {
    this.errorLog.push(error.toJSON());

    // Trim log if too large
    if (this.errorLog.length > this.maxLogSize) {
      this.errorLog.shift();
    }

    // Console log based on severity
    const logMethod = error.severity === ErrorSeverity.FATAL ? 'error'
      : error.severity === ErrorSeverity.ERROR ? 'error'
      : error.severity === ErrorSeverity.WARNING ? 'warn'
      : 'info';

    console[logMethod](`[${error.category}] ${error.message}`, {
      code: error.code,
      context: error.context
    });
  }

  /**
   * Get error statistics
   * @returns {Object}
   */
  getStatistics() {
    const stats = {
      total: this.errorLog.length,
      byCategory: {},
      bySeverity: {},
      byCode: {},
      recent: this.errorLog.slice(-10)
    };

    for (const error of this.errorLog) {
      // By category
      stats.byCategory[error.category] = (stats.byCategory[error.category] || 0) + 1;

      // By severity
      stats.bySeverity[error.severity] = (stats.bySeverity[error.severity] || 0) + 1;

      // By code
      stats.byCode[error.code] = (stats.byCode[error.code] || 0) + 1;
    }

    return stats;
  }

  /**
   * Clear error log
   */
  clearLog() {
    this.errorLog = [];
  }

  /**
   * Check if error is recoverable
   * @param {Error} error - Error to check
   * @returns {boolean}
   */
  isRecoverable(error) {
    if (error instanceof ScanError) {
      return error.recoverable;
    }
    return true; // Assume recoverable by default
  }
}
