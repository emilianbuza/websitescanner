# Migration Guide: Old → New Architecture

This guide helps you migrate from the old monolithic architecture to the new agent-based system.

---

## Why Migrate?

The old architecture has critical flaws:
- ❌ Monolithic 1139-line God class
- ❌ Cannot run scans in parallel
- ❌ Hardcoded business logic
- ❌ Poor testability
- ❌ No progress tracking
- ❌ State management issues
- ❌ High coupling, low cohesion

The new architecture provides:
- ✅ Modular agent-based design
- ✅ Parallel agent execution (3x faster)
- ✅ Full testability
- ✅ Progress tracking
- ✅ Immutable state
- ✅ Clear separation of concerns
- ✅ Easy extensibility

---

## Migration Strategy

We recommend a **phased migration** approach:

### Phase 1: Dual System (Recommended)
Run both systems in parallel, gradually migrate endpoints.

### Phase 2: Feature Parity
Ensure new system matches old system functionality.

### Phase 3: Deprecation
Mark old endpoints as deprecated.

### Phase 4: Removal
Remove old code after migration complete.

---

## Step-by-Step Migration

### Step 1: Install Dependencies

No new dependencies needed! The new architecture uses the same dependencies:
- Playwright (already installed)
- Express (already installed)
- better-sqlite3 (already installed)

### Step 2: Import New Components

```javascript
// Old imports
import { UltimateWebsiteScanner } from './server.js';

// New imports
import { ScanOrchestrator } from './src/core/ScanOrchestrator.js';
import { createDefaultConfig } from './src/core/ScanContext.js';
import { EventBus } from './src/infrastructure/EventBus.js';
import { ErrorHandler } from './src/infrastructure/ErrorHandler.js';
import { ConsentAgent } from './src/agents/ConsentAgent.js';
import { MarketingTagAgent } from './src/agents/MarketingTagAgent.js';
```

### Step 3: Create Orchestrator

```javascript
// Old code
const scanner = new UltimateWebsiteScanner();
scanner.reset(); // Must reset between scans!

// New code
const eventBus = new EventBus();
const errorHandler = new ErrorHandler(eventBus);
const orchestrator = new ScanOrchestrator({
  agents: [
    new ConsentAgent(),
    new MarketingTagAgent()
    // Add more agents as needed
  ],
  eventBus,
  errorHandler
});
```

**Benefits:**
- No need to reset
- Stateless, can run multiple scans concurrently
- Built-in error handling and retry logic

### Step 4: Update Scan Endpoints

#### Old `/scan` endpoint:
```javascript
app.post('/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing URL' });

  try {
    const scanner = new UltimateWebsiteScanner();
    const results = await scanner.scanWithRetry(url);

    const scanId = saveScan(url, results);
    results.scanId = scanId;

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Scan failed', details: error.message });
  }
});
```

#### New `/scan-v3` endpoint:
```javascript
app.post('/scan-v3', async (req, res) => {
  const { url, config } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing URL' });

  try {
    // Create orchestrator (or reuse singleton)
    const orchestrator = createOrchestrator();

    // Use provided config or default
    const scanConfig = config || createDefaultConfig();

    // Execute scan
    const result = await orchestrator.executeScan(url, scanConfig);

    // Save to database
    const scanId = saveScan(url, result);
    result.scanId = scanId;

    // Return result
    res.json({
      ok: true,
      ...result
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error.message,
      code: error.code,
      category: error.category
    });
  }
});
```

#### Add Progress Streaming (Optional):
```javascript
app.post('/scan-v3-stream', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing URL' });

  // Set up SSE (Server-Sent Events)
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const orchestrator = createOrchestrator();

  // Listen to progress events
  orchestrator.eventBus.on('progress', (event) => {
    res.write(`data: ${JSON.stringify(event.data)}\n\n`);
  });

  try {
    const result = await orchestrator.executeScan(url, createDefaultConfig());
    res.write(`data: ${JSON.stringify({ type: 'complete', result })}\n\n`);
    res.end();
  } catch (error) {
    res.write(`data: ${JSON.stringify({ type: 'error', error: error.message })}\n\n`);
    res.end();
  }
});
```

---

## Feature Mapping

### Old Code → New Code Mapping

#### 1. Scanning
```javascript
// Old
const scanner = new UltimateWebsiteScanner();
const results = await scanner.scan(url);

// New
const orchestrator = new ScanOrchestrator({ agents, eventBus, errorHandler });
const result = await orchestrator.executeScan(url, config);
```

#### 2. Consent Handling
```javascript
// Old
await scanner.handleConsent(page, 'accept');

// New
// Handled automatically by ScanOrchestrator based on mode
// Or implement custom ConsentAgent
```

#### 3. Marketing Tag Detection
```javascript
// Old
const tags = await scanner.checkMarketingTagsDeep(page, requestLog);

// New
const marketingAgent = new MarketingTagAgent();
const result = await marketingAgent.execute(context);
```

#### 4. Compliance Analysis
```javascript
// Old
scanner.analyzeConsentCompliance();
const compliance = scanner.marketingTags;

// New
// Findings are automatically aggregated
const complianceFindings = result.allFindings.filter(
  f => f.type === 'tool_compliance'
);
```

#### 5. Error Handling
```javascript
// Old
try {
  await page.goto(url);
} catch (error) {
  console.log(`Failed: ${error.message}`);
  // Maybe retry manually?
}

// New
const result = await errorHandler.withRetry(
  () => page.goto(url),
  { category: ErrorCategory.NETWORK }
);
```

#### 6. Progress Tracking
```javascript
// Old
// No progress tracking ❌

// New
eventBus.on('progress', (event) => {
  console.log(`${event.data.progress}% - ${event.data.message}`);
});
```

---

## Database Migration

### Scan Result Format Changes

#### Old Format:
```json
{
  "version": "2.4.0",
  "scannedUrl": "https://example.com",
  "timestamp": "14.11.2025, 10:30:15",
  "summary": {
    "totalIssues": 42,
    "highPriorityIssues": 5,
    "marketingTags": [/* array */]
  },
  "details": {
    "errors": [/* array */],
    "networkIssues": [/* array */],
    "cspViolations": [/* array */]
  },
  "evidence": { /* object */ },
  "rawResults": {
    "withoutConsent": { /* object */ },
    "withConsent": { /* object */ },
    "withReject": { /* object */ }
  }
}
```

#### New Format:
```json
{
  "scanId": "scan_1699951815123_abc123",
  "url": "https://example.com",
  "timestamp": "2025-11-14T10:30:15.123Z",
  "agentResults": [
    {
      "agentName": "consent",
      "success": true,
      "findings": [/* array */],
      "metadata": {
        "duration": 2345,
        "startTime": "2025-11-14T10:30:15.123Z",
        "endTime": "2025-11-14T10:30:17.468Z"
      },
      "errors": []
    }
  ],
  "allFindings": [/* flattened from all agents */],
  "summary": {
    "totalFindings": 42,
    "criticalFindings": 2,
    "highFindings": 5,
    "successfulAgents": 5,
    "failedAgents": 0
  },
  "score": 78,
  "duration": 12345
}
```

### Adapter for Old Format
```javascript
/**
 * Convert new format to old format for backward compatibility
 */
function convertToOldFormat(newResult) {
  return {
    version: '2.5.0-compat',
    scannedUrl: newResult.url,
    timestamp: new Date(newResult.timestamp).toLocaleString('de-DE'),
    summary: {
      totalIssues: newResult.summary.totalFindings,
      highPriorityIssues: newResult.summary.criticalFindings + newResult.summary.highFindings,
      marketingTags: extractMarketingTags(newResult.allFindings)
    },
    details: {
      errors: newResult.allFindings.filter(f => f.type.includes('error')),
      networkIssues: newResult.allFindings.filter(f => f.source === 'network'),
      cspViolations: newResult.allFindings.filter(f => f.type === 'csp_violation')
    },
    // Map other fields as needed
  };
}
```

---

## Frontend Migration

### Old API Calls
```javascript
// Old frontend code
const response = await fetch('/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url })
});
const results = await response.json();
```

### New API Calls with Progress
```javascript
// New frontend code with SSE progress
const eventSource = new EventSource(`/scan-v3-stream?url=${encodeURIComponent(url)}`);

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);

  if (data.type === 'progress') {
    // Update progress bar
    updateProgressBar(data.progress, data.message);
  } else if (data.type === 'complete') {
    // Scan finished
    displayResults(data.result);
    eventSource.close();
  } else if (data.type === 'error') {
    // Handle error
    showError(data.error);
    eventSource.close();
  }
};
```

Or use regular polling:
```javascript
// Start scan
const startResponse = await fetch('/scan-v3', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url })
});
const { scanId } = await startResponse.json();

// Poll for progress
const interval = setInterval(async () => {
  const progressResponse = await fetch(`/api/scan/${scanId}/progress`);
  const { progress, status, result } = await progressResponse.json();

  updateProgressBar(progress);

  if (status === 'completed') {
    clearInterval(interval);
    displayResults(result);
  }
}, 1000);
```

---

## Common Migration Issues

### Issue 1: "Agent not found"

**Problem:** Agent not registered or not in enabled list

**Solution:**
```javascript
// Ensure agent is registered
orchestrator.registerAgent(new MyAgent());

// Ensure agent is in enabled list
const config = createDefaultConfig();
config.enabledAgents.push('my-agent');
```

### Issue 2: "Cannot read property 'page' of null"

**Problem:** Context not initialized with browser

**Solution:**
```javascript
// Old code creates its own browser
// New code: Orchestrator handles browser automatically

// If you need custom browser setup:
const browser = await chromium.launch({ /* options */ });
const browserContext = await browser.newContext();
const page = await browserContext.newPage();

const context = new ScanContext({ url, mode, config })
  .withBrowser(browser, browserContext, page);
```

### Issue 3: "Circular dependency detected"

**Problem:** Agents depend on each other circularly

**Solution:**
```javascript
// Remove circular dependencies
// Agent A should not depend on Agent B if Agent B depends on Agent A

// ✅ Good
ConsentAgent: dependencies: []
MarketingAgent: dependencies: ['consent']
SecurityAgent: dependencies: ['consent', 'marketing']

// ❌ Bad
ConsentAgent: dependencies: ['marketing']
MarketingAgent: dependencies: ['consent']
```

### Issue 4: Results format different

**Problem:** Frontend expects old format

**Solution:** Use adapter function
```javascript
app.post('/scan-legacy', async (req, res) => {
  const newResult = await orchestrator.executeScan(url, config);
  const oldFormat = convertToOldFormat(newResult);
  res.json(oldFormat);
});
```

---

## Testing Your Migration

### 1. Compare Results

Run both systems side-by-side and compare:

```javascript
// Compare scan results
const oldResult = await oldScanner.scan(url);
const newResult = await orchestrator.executeScan(url, config);

console.log('Old findings:', oldResult.details.errors.length);
console.log('New findings:', newResult.allFindings.length);

// Check for missing findings
const oldIssues = new Set(oldResult.details.errors.map(e => e.type));
const newIssues = new Set(newResult.allFindings.map(f => f.type));

const missing = [...oldIssues].filter(x => !newIssues.has(x));
if (missing.length > 0) {
  console.warn('Missing in new:', missing);
}
```

### 2. Performance Comparison

```javascript
console.time('Old scan');
await oldScanner.scan(url);
console.timeEnd('Old scan');

console.time('New scan');
await orchestrator.executeScan(url, config);
console.timeEnd('New scan');

// Expected: New scan is 2-3x faster due to parallel execution
```

### 3. Load Testing

```javascript
// Test concurrent scans (old system cannot do this)
const urls = [
  'https://example1.com',
  'https://example2.com',
  'https://example3.com'
];

// Old: Must run sequentially
for (const url of urls) {
  const scanner = new UltimateWebsiteScanner();
  await scanner.scan(url);
}

// New: Can run in parallel
await Promise.all(
  urls.map(url => orchestrator.executeScan(url, config))
);
```

---

## Rollback Plan

If you need to rollback:

1. Keep old code in separate files (e.g., `server.old.js`)
2. Use feature flags to switch between systems
3. Monitor error rates and performance
4. Be ready to switch back if issues arise

```javascript
const USE_NEW_ARCHITECTURE = process.env.USE_NEW_ARCH === 'true';

app.post('/scan', async (req, res) => {
  if (USE_NEW_ARCHITECTURE) {
    return handleScanNew(req, res);
  } else {
    return handleScanOld(req, res);
  }
});
```

---

## Timeline

Recommended migration timeline:

- **Week 1:** Set up new architecture, create agents
- **Week 2:** Test new system, compare with old
- **Week 3:** Deploy both systems in parallel (feature flag)
- **Week 4:** Monitor and fix issues
- **Week 5:** Gradually shift traffic to new system
- **Week 6:** Deprecate old endpoints
- **Week 7:** Remove old code

---

## Support

Need help with migration?

1. Review `DESIGN_REVIEW.md` for architecture details
2. Check `NEW_ARCHITECTURE_README.md` for API docs
3. See `src/example.js` for usage examples
4. Open an issue with migration questions

---

## Checklist

Use this checklist to track your migration:

- [ ] Read design review and architecture docs
- [ ] Set up new directory structure (`src/`)
- [ ] Create EventBus and ErrorHandler instances
- [ ] Implement/migrate agents (Consent, Marketing, Security, etc.)
- [ ] Create ScanOrchestrator
- [ ] Add new `/scan-v3` endpoint
- [ ] Add progress tracking (optional)
- [ ] Test new system thoroughly
- [ ] Deploy both systems in parallel
- [ ] Monitor metrics and errors
- [ ] Migrate frontend to new API
- [ ] Update database to handle both formats
- [ ] Deprecate old endpoints
- [ ] Remove old code

---

**Last Updated:** 2025-11-14
**Status:** Ready for Migration
