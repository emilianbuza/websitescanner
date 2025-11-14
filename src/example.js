/**
 * Example usage of the new agent-based scanner architecture
 */

import { ScanOrchestrator } from './core/ScanOrchestrator.js';
import { createDefaultConfig } from './core/ScanContext.js';
import { EventBus } from './infrastructure/EventBus.js';
import { ErrorHandler } from './infrastructure/ErrorHandler.js';

// Import agents
import { ConsentAgent } from './agents/ConsentAgent.js';
import { MarketingTagAgent } from './agents/MarketingTagAgent.js';

/**
 * Example 1: Basic scan with default configuration
 */
async function basicScan() {
  console.log('=== Example 1: Basic Scan ===\n');

  // Create event bus and error handler
  const eventBus = new EventBus();
  const errorHandler = new ErrorHandler(eventBus);

  // Register event listeners for progress tracking
  eventBus.on('progress', (event) => {
    console.log(`[Progress] ${event.data.stage}: ${event.data.progress}% - ${event.data.message}`);
  });

  eventBus.on('agent:started', (event) => {
    console.log(`[Agent] Started: ${event.data.agentName}`);
  });

  eventBus.on('agent:completed', (event) => {
    console.log(
      `[Agent] Completed: ${event.data.agentName} - ` +
      `${event.data.success ? 'Success' : 'Failed'} - ` +
      `${event.data.findingCount} findings in ${event.data.duration}ms`
    );
  });

  // Create agents
  const agents = [
    new ConsentAgent(),
    new MarketingTagAgent()
  ];

  // Create orchestrator
  const orchestrator = new ScanOrchestrator({
    agents,
    eventBus,
    errorHandler
  });

  try {
    // Execute scan
    const result = await orchestrator.executeScan(
      'https://www.example.com',
      createDefaultConfig()
    );

    console.log('\n=== Scan Results ===');
    console.log(`Scan ID: ${result.scanId}`);
    console.log(`URL: ${result.url}`);
    console.log(`Duration: ${result.duration}ms`);
    console.log(`Score: ${result.score}/100`);
    console.log(`Total Findings: ${result.allFindings.length}`);
    console.log(`Successful Agents: ${result.summary.successfulAgents}`);
    console.log(`Failed Agents: ${result.summary.failedAgents}`);

    // Display findings by severity
    console.log('\n=== Findings by Severity ===');
    const bySeverity = result.allFindings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {});
    console.log(JSON.stringify(bySeverity, null, 2));

    // Display some example findings
    console.log('\n=== Example Findings ===');
    result.allFindings.slice(0, 5).forEach(finding => {
      console.log(`\n[${finding.severity.toUpperCase()}] ${finding.type}`);
      console.log(`  Source: ${finding.source}`);
      console.log(`  Message: ${finding.message}`);
      console.log(`  Evidence: ${JSON.stringify(finding.evidence, null, 2).substring(0, 200)}...`);
    });

    return result;
  } catch (error) {
    console.error('\n=== Scan Failed ===');
    console.error(`Error: ${error.message}`);
    console.error(`Category: ${error.category}`);
    console.error(`Recoverable: ${error.recoverable}`);
    throw error;
  }
}

/**
 * Example 2: Custom configuration with specific agents
 */
async function customScan() {
  console.log('\n\n=== Example 2: Custom Configuration ===\n');

  const eventBus = new EventBus();
  const errorHandler = new ErrorHandler(eventBus);

  // Create custom configuration
  const customConfig = {
    timeout: 30000,
    waitAfterConsent: 2000,
    maxRetries: 3,
    headless: true,
    enabledAgents: ['consent', 'marketing'], // Only these agents
    agentConfigs: {
      consent: {
        acceptPatterns: [/accept|agree/i],
        rejectPatterns: [/reject|decline/i]
      },
      marketing: {
        timeout: 8000,
        deepScan: true
      }
    }
  };

  // Create specialized agents with custom options
  const agents = [
    new ConsentAgent({ priority: 5, timeout: 12000 }),
    new MarketingTagAgent({ priority: 10, timeout: 15000 })
  ];

  const orchestrator = new ScanOrchestrator({ agents, eventBus, errorHandler });

  try {
    const result = await orchestrator.executeScan(
      'https://www.example.com',
      customConfig
    );

    console.log('\n=== Custom Scan Results ===');
    console.log(`Total Findings: ${result.allFindings.length}`);
    console.log(`Score: ${result.score}/100`);

    return result;
  } catch (error) {
    console.error('Custom scan failed:', error.message);
    throw error;
  }
}

/**
 * Example 3: Error handling and retry logic
 */
async function scanWithErrorHandling() {
  console.log('\n\n=== Example 3: Error Handling ===\n');

  const eventBus = new EventBus();
  const errorHandler = new ErrorHandler(eventBus);

  // Listen for error events
  eventBus.on('error', (event) => {
    console.log(`[Error] ${event.data.code}: ${event.data.message}`);
  });

  // Custom retry strategy for network errors
  errorHandler.registerRetryStrategy('network', {
    maxRetries: 4,
    backoff: 'exponential',
    initialDelay: 2000,
    maxDelay: 10000
  });

  const agents = [new ConsentAgent(), new MarketingTagAgent()];
  const orchestrator = new ScanOrchestrator({ agents, eventBus, errorHandler });

  try {
    // This might fail with network errors, but will retry
    const result = await orchestrator.executeScan(
      'https://www.example.com',
      createDefaultConfig()
    );

    console.log('\n=== Scan succeeded after retries ===');
    console.log(`Duration: ${result.duration}ms`);

    // Check error statistics
    const errorStats = errorHandler.getStatistics();
    console.log('\n=== Error Statistics ===');
    console.log(`Total Errors: ${errorStats.total}`);
    console.log(`By Category: ${JSON.stringify(errorStats.byCategory, null, 2)}`);
    console.log(`By Severity: ${JSON.stringify(errorStats.bySeverity, null, 2)}`);

    return result;
  } catch (error) {
    console.error('\n=== Scan failed after all retries ===');
    console.error(`Final error: ${error.message}`);
    throw error;
  }
}

/**
 * Example 4: Event-driven progress tracking
 */
async function scanWithProgressTracking() {
  console.log('\n\n=== Example 4: Progress Tracking ===\n');

  const eventBus = new EventBus();
  const errorHandler = new ErrorHandler(eventBus);

  // Track progress with a progress bar simulation
  let lastProgress = 0;
  eventBus.on('progress', (event) => {
    const progress = event.data.progress;
    if (progress > lastProgress) {
      const bar = '█'.repeat(Math.floor(progress / 2)) + '░'.repeat(50 - Math.floor(progress / 2));
      console.log(`[${bar}] ${progress}% - ${event.data.message}`);
      lastProgress = progress;
    }
  });

  // Track agent execution times
  const agentTimes = {};
  eventBus.on('agent:started', (event) => {
    agentTimes[event.data.agentName] = Date.now();
  });

  eventBus.on('agent:completed', (event) => {
    const duration = Date.now() - agentTimes[event.data.agentName];
    console.log(`  ✓ ${event.data.agentName} completed in ${duration}ms`);
  });

  const agents = [new ConsentAgent(), new MarketingTagAgent()];
  const orchestrator = new ScanOrchestrator({ agents, eventBus, errorHandler });

  try {
    const result = await orchestrator.executeScan(
      'https://www.example.com',
      createDefaultConfig()
    );

    console.log('\n✅ Scan completed successfully!');
    console.log(`Total duration: ${result.duration}ms`);
    console.log(`Score: ${result.score}/100`);

    return result;
  } catch (error) {
    console.error('\n❌ Scan failed:', error.message);
    throw error;
  }
}

/**
 * Example 5: Dynamic agent registration
 */
async function scanWithDynamicAgents() {
  console.log('\n\n=== Example 5: Dynamic Agent Registration ===\n');

  const eventBus = new EventBus();
  const errorHandler = new ErrorHandler(eventBus);

  // Start with empty agent list
  const orchestrator = new ScanOrchestrator({ agents: [], eventBus, errorHandler });

  // Register agents dynamically
  console.log('Registering agents dynamically...');
  orchestrator.registerAgent(new ConsentAgent());
  orchestrator.registerAgent(new MarketingTagAgent());

  // Check registered agents
  const registeredAgents = orchestrator.getAgents();
  console.log(`Registered ${registeredAgents.length} agents:`);
  registeredAgents.forEach(agent => {
    console.log(`  - ${agent.name} (priority: ${agent.priority}, version: ${agent.version})`);
  });

  try {
    const result = await orchestrator.executeScan(
      'https://www.example.com',
      createDefaultConfig()
    );

    console.log('\n=== Scan Results ===');
    console.log(`Agents executed: ${result.agentResults.length}`);
    console.log(`Findings: ${result.allFindings.length}`);

    return result;
  } catch (error) {
    console.error('Scan failed:', error.message);
    throw error;
  }
}

/**
 * Example 6: Waiting for specific events
 */
async function scanWithEventWaiting() {
  console.log('\n\n=== Example 6: Waiting for Events ===\n');

  const eventBus = new EventBus();
  const errorHandler = new ErrorHandler(eventBus);
  const agents = [new ConsentAgent(), new MarketingTagAgent()];
  const orchestrator = new ScanOrchestrator({ agents, eventBus, errorHandler });

  // Start scan (don't await)
  const scanPromise = orchestrator.executeScan(
    'https://www.example.com',
    createDefaultConfig()
  );

  // Wait for specific events
  try {
    console.log('Waiting for consent agent to complete...');
    const consentEvent = await eventBus.waitFor('agent:completed', {
      timeout: 30000,
      condition: (event) => event.data.agentName === 'consent'
    });
    console.log(`✓ Consent agent completed with ${consentEvent.data.findingCount} findings`);

    console.log('Waiting for marketing agent to complete...');
    const marketingEvent = await eventBus.waitFor('agent:completed', {
      timeout: 30000,
      condition: (event) => event.data.agentName === 'marketing'
    });
    console.log(`✓ Marketing agent completed with ${marketingEvent.data.findingCount} findings`);

    // Now wait for full scan to complete
    const result = await scanPromise;
    console.log('\n✅ Full scan completed!');

    return result;
  } catch (error) {
    console.error('Event waiting failed:', error.message);
    throw error;
  }
}

// Main execution
async function main() {
  try {
    // Run examples
    await basicScan();
    // await customScan();
    // await scanWithErrorHandling();
    // await scanWithProgressTracking();
    // await scanWithDynamicAgents();
    // await scanWithEventWaiting();

    console.log('\n\n✅ All examples completed successfully!');
  } catch (error) {
    console.error('\n\n❌ Example failed:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export {
  basicScan,
  customScan,
  scanWithErrorHandling,
  scanWithProgressTracking,
  scanWithDynamicAgents,
  scanWithEventWaiting
};
