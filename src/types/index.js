/**
 * Type definitions for the agent-based scanner architecture
 * Using JSDoc for type safety without TypeScript
 */

/**
 * @typedef {Object} ScanConfig
 * @property {number} timeout - Page load timeout in ms
 * @property {number} waitAfterConsent - Wait time after consent action in ms
 * @property {number} maxRetries - Maximum retry attempts
 * @property {boolean} headless - Run browser in headless mode
 * @property {string[]} enabledAgents - List of enabled agent names
 * @property {Object} agentConfigs - Agent-specific configurations
 */

/**
 * @typedef {'no-consent' | 'accept' | 'reject'} ConsentMode
 */

/**
 * @typedef {Object} ScanContextData
 * @property {string} url - Target URL to scan
 * @property {ConsentMode} mode - Current consent mode
 * @property {ScanConfig} config - Scan configuration
 * @property {Object} [browser] - Playwright browser instance
 * @property {Object} [context] - Playwright browser context
 * @property {Object} [page] - Playwright page instance
 * @property {Map<string, any>} metadata - Additional metadata
 */

/**
 * @typedef {'critical' | 'high' | 'medium' | 'low' | 'info'} Severity
 */

/**
 * @typedef {Object} Finding
 * @property {string} type - Finding type (e.g., 'csp_violation', 'tracking_hit')
 * @property {Severity} severity - Severity level
 * @property {string} session - Session/mode identifier
 * @property {string} message - Human-readable message
 * @property {Object} evidence - Evidence data
 * @property {string} source - Source of finding (agent name)
 * @property {string} [toolName] - Detected tool name (if applicable)
 * @property {string} [category] - Category of finding
 * @property {Date} timestamp - When finding was detected
 */

/**
 * @typedef {Object} AgentMetadata
 * @property {number} duration - Execution duration in ms
 * @property {Date} startTime - Start timestamp
 * @property {Date} endTime - End timestamp
 * @property {number} retries - Number of retries
 * @property {string} version - Agent version
 */

/**
 * @typedef {Object} AgentError
 * @property {string} message - Error message
 * @property {string} code - Error code
 * @property {string} [stack] - Stack trace
 * @property {boolean} recoverable - Whether error is recoverable
 * @property {Date} timestamp - Error timestamp
 */

/**
 * @typedef {Object} AgentResult
 * @property {string} agentName - Name of agent
 * @property {boolean} success - Whether execution succeeded
 * @property {Finding[]} findings - List of findings
 * @property {AgentMetadata} metadata - Agent execution metadata
 * @property {AgentError[]} errors - Errors encountered
 */

/**
 * @typedef {Object} ScanResult
 * @property {string} scanId - Unique scan identifier
 * @property {string} url - Scanned URL
 * @property {Date} timestamp - Scan timestamp
 * @property {AgentResult[]} agentResults - Results from all agents
 * @property {Finding[]} allFindings - Aggregated findings
 * @property {Object} summary - Scan summary
 * @property {number} score - Overall compliance score
 * @property {number} duration - Total scan duration in ms
 */

/**
 * @typedef {Object} EventPayload
 * @property {string} eventType - Type of event
 * @property {string} source - Event source
 * @property {any} data - Event data
 * @property {Date} timestamp - Event timestamp
 */

/**
 * @typedef {Object} ProgressEvent
 * @property {string} stage - Current stage
 * @property {number} progress - Progress percentage (0-100)
 * @property {string} message - Progress message
 * @property {Object} [data] - Additional data
 */

export default {};
