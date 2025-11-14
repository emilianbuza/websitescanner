/**
 * Event bus for agent communication and progress tracking
 * Implements pub/sub pattern with event filtering
 */
export class EventBus {
  constructor() {
    this.listeners = new Map();
    this.eventHistory = [];
    this.maxHistorySize = 1000;
  }

  /**
   * Subscribe to events
   * @param {string} eventType - Event type to listen for (use '*' for all events)
   * @param {Function} handler - Event handler function
   * @param {Object} [options] - Subscription options
   * @param {number} [options.priority] - Handler priority (lower = earlier)
   * @param {Function} [options.filter] - Filter function
   * @returns {Function} Unsubscribe function
   */
  on(eventType, handler, options = {}) {
    if (typeof handler !== 'function') {
      throw new Error('Handler must be a function');
    }

    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, []);
    }

    const listener = {
      handler,
      priority: options.priority ?? 100,
      filter: options.filter ?? (() => true),
      id: Math.random().toString(36).substr(2, 9)
    };

    const listeners = this.listeners.get(eventType);
    listeners.push(listener);

    // Sort by priority
    listeners.sort((a, b) => a.priority - b.priority);

    // Return unsubscribe function
    return () => this.off(eventType, listener.id);
  }

  /**
   * Subscribe to events (one-time)
   * @param {string} eventType - Event type
   * @param {Function} handler - Event handler
   * @param {Object} [options] - Subscription options
   * @returns {Function} Unsubscribe function
   */
  once(eventType, handler, options = {}) {
    const unsubscribe = this.on(
      eventType,
      async (event) => {
        unsubscribe();
        return handler(event);
      },
      options
    );
    return unsubscribe;
  }

  /**
   * Unsubscribe from events
   * @param {string} eventType - Event type
   * @param {string} listenerId - Listener ID
   */
  off(eventType, listenerId) {
    if (!this.listeners.has(eventType)) return;

    const listeners = this.listeners.get(eventType);
    const index = listeners.findIndex(l => l.id === listenerId);

    if (index !== -1) {
      listeners.splice(index, 1);
    }

    if (listeners.length === 0) {
      this.listeners.delete(eventType);
    }
  }

  /**
   * Emit an event
   * @param {string} eventType - Event type
   * @param {Object} data - Event data
   * @param {Object} [metadata] - Additional metadata
   * @returns {Promise<void>}
   */
  async emit(eventType, data, metadata = {}) {
    const event = {
      type: eventType,
      data,
      metadata: {
        ...metadata,
        timestamp: new Date(),
        id: Math.random().toString(36).substr(2, 9)
      }
    };

    // Store in history
    this.eventHistory.push(event);
    if (this.eventHistory.length > this.maxHistorySize) {
      this.eventHistory.shift();
    }

    // Get listeners for this event type and wildcard
    const specificListeners = this.listeners.get(eventType) || [];
    const wildcardListeners = this.listeners.get('*') || [];
    const allListeners = [...specificListeners, ...wildcardListeners];

    // Execute handlers
    const promises = allListeners
      .filter(listener => listener.filter(event))
      .map(listener =>
        Promise.resolve()
          .then(() => listener.handler(event))
          .catch(error => {
            console.error(`Event handler error for ${eventType}:`, error);
            return null;
          })
      );

    await Promise.all(promises);
  }

  /**
   * Emit progress event
   * @param {string} stage - Current stage
   * @param {number} progress - Progress percentage (0-100)
   * @param {string} message - Progress message
   * @param {Object} [data] - Additional data
   * @returns {Promise<void>}
   */
  async emitProgress(stage, progress, message, data = {}) {
    return this.emit('progress', {
      stage,
      progress: Math.min(100, Math.max(0, progress)),
      message,
      ...data
    });
  }

  /**
   * Emit error event
   * @param {Error} error - Error object
   * @param {Object} [context] - Error context
   * @returns {Promise<void>}
   */
  async emitError(error, context = {}) {
    return this.emit('error', {
      message: error.message,
      code: error.code || 'UNKNOWN_ERROR',
      stack: error.stack,
      ...context
    });
  }

  /**
   * Emit agent started event
   * @param {string} agentName - Agent name
   * @param {Object} [data] - Additional data
   * @returns {Promise<void>}
   */
  async emitAgentStarted(agentName, data = {}) {
    return this.emit('agent:started', {
      agentName,
      ...data
    });
  }

  /**
   * Emit agent completed event
   * @param {string} agentName - Agent name
   * @param {import('../types/index.js').AgentResult} result - Agent result
   * @returns {Promise<void>}
   */
  async emitAgentCompleted(agentName, result) {
    return this.emit('agent:completed', {
      agentName,
      success: result.success,
      findingCount: result.findings.length,
      errorCount: result.errors.length,
      duration: result.metadata.duration
    });
  }

  /**
   * Get event history
   * @param {Object} [filter] - Filter options
   * @param {string} [filter.type] - Filter by event type
   * @param {Date} [filter.since] - Filter by timestamp
   * @param {number} [filter.limit] - Limit results
   * @returns {Array}
   */
  getHistory(filter = {}) {
    let events = [...this.eventHistory];

    if (filter.type) {
      events = events.filter(e => e.type === filter.type);
    }

    if (filter.since) {
      events = events.filter(e => e.metadata.timestamp >= filter.since);
    }

    if (filter.limit) {
      events = events.slice(-filter.limit);
    }

    return events;
  }

  /**
   * Clear event history
   */
  clearHistory() {
    this.eventHistory = [];
  }

  /**
   * Get active listener count
   * @returns {number}
   */
  getListenerCount() {
    let count = 0;
    for (const listeners of this.listeners.values()) {
      count += listeners.length;
    }
    return count;
  }

  /**
   * Clear all listeners
   */
  clearListeners() {
    this.listeners.clear();
  }

  /**
   * Wait for an event to occur
   * @param {string} eventType - Event type to wait for
   * @param {Object} [options] - Wait options
   * @param {number} [options.timeout] - Timeout in ms
   * @param {Function} [options.condition] - Condition function
   * @returns {Promise<Object>} Event data
   */
  async waitFor(eventType, options = {}) {
    return new Promise((resolve, reject) => {
      const timeout = options.timeout || 30000;
      const condition = options.condition || (() => true);

      let timeoutId;
      const unsubscribe = this.on(eventType, (event) => {
        if (condition(event)) {
          clearTimeout(timeoutId);
          unsubscribe();
          resolve(event);
        }
      });

      timeoutId = setTimeout(() => {
        unsubscribe();
        reject(new Error(`Timeout waiting for event: ${eventType}`));
      }, timeout);
    });
  }
}

/**
 * Create a global event bus instance
 */
export const globalEventBus = new EventBus();
