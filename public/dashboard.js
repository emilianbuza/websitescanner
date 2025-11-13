// dashboard.js
// Enhanced Dashboard Features: Charts, History, PDF Export, Comparison

let chartInstances = {};

// Initialize Dashboard
async function initDashboard() {
  await loadHistory();
  await loadStats();
  setupPDFExport();
  setupHistoryHandlers();
}

// Load Scan History
async function loadHistory() {
  try {
    const response = await fetch('/api/history?limit=20');
    const data = await response.json();

    if (data.ok && data.history) {
      renderHistory(data.history);
    }
  } catch (error) {
    console.error('Failed to load history:', error);
  }
}

// Render History List
function renderHistory(history) {
  const historyContainer = document.getElementById('historyList');
  if (!historyContainer) return;

  if (history.length === 0) {
    historyContainer.innerHTML = '<div class="empty">Noch keine Scans vorhanden.</div>';
    return;
  }

  historyContainer.innerHTML = history.map(scan => `
    <div class="history-item" onclick="loadScan(${scan.id})">
      <div class="history-header">
        <div class="history-url">${escapeHtml(scan.url)}</div>
        <div class="history-score score-${getScoreClass(scan.score)}">${scan.score}/100</div>
      </div>
      <div class="history-meta">
        <span class="history-date">${formatDate(scan.created_at)}</span>
        <span class="history-issues">${scan.critical_issues} kritische Probleme</span>
        <div class="history-actions">
          <button onclick="event.stopPropagation(); loadScan(${scan.id})" class="btn-small">Anzeigen</button>
          <button onclick="event.stopPropagation(); exportScanPDF(${scan.id})" class="btn-small">PDF</button>
          <button onclick="event.stopPropagation(); deleteScanPrompt(${scan.id})" class="btn-small btn-danger">Löschen</button>
        </div>
      </div>
    </div>
  `).join('');
}

// Load specific scan
async function loadScan(scanId) {
  try {
    const response = await fetch(`/api/scan/${scanId}`);
    const data = await response.json();

    if (data.ok && data.scan) {
      DATA = data.scan.scan_data;
      renderAll();

      // Switch to results view
      document.getElementById('heroSection').style.display = 'none';
      document.getElementById('exampleSection').style.display = 'none';
      document.getElementById('urgencyBanner').style.display = 'none';
      document.getElementById('mainApp').style.display = 'block';

      showBanner('Scan geladen!');
    }
  } catch (error) {
    console.error('Failed to load scan:', error);
    showBanner('❌ Fehler beim Laden');
  }
}

// Delete Scan
async function deleteScanPrompt(scanId) {
  if (!confirm('Möchten Sie diesen Scan wirklich löschen?')) return;

  try {
    const response = await fetch(`/api/scan/${scanId}`, { method: 'DELETE' });
    const data = await response.json();

    if (data.ok) {
      showBanner('✅ Scan gelöscht');
      await loadHistory();
    }
  } catch (error) {
    console.error('Failed to delete scan:', error);
    showBanner('❌ Fehler beim Löschen');
  }
}

// Load Statistics
async function loadStats() {
  try {
    const response = await fetch('/api/stats');
    const data = await response.json();

    if (data.ok && data.stats) {
      renderStats(data.stats);
    }
  } catch (error) {
    console.error('Failed to load stats:', error);
  }
}

// Render Statistics
function renderStats(stats) {
  const statsContainer = document.getElementById('statsOverview');
  if (!statsContainer) return;

  statsContainer.innerHTML = `
    <div class="stat-card">
      <div class="stat-value">${stats.total_scans || 0}</div>
      <div class="stat-label">Gesamt Scans</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">${stats.unique_urls || 0}</div>
      <div class="stat-label">Websites</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">${Math.round(stats.avg_score || 0)}/100</div>
      <div class="stat-label">Ø Score</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">${Math.round(stats.avg_critical || 0)}</div>
      <div class="stat-label">Ø Kritische</div>
    </div>
  `;
}

// Setup PDF Export
function setupPDFExport() {
  const pdfBtn = document.getElementById('exportPDFBtn');
  if (pdfBtn) {
    pdfBtn.addEventListener('click', () => exportCurrentScanPDF());
  }
}

// Export Current Scan as PDF
async function exportCurrentScanPDF() {
  if (!DATA) {
    showBanner('❌ Keine Scan-Daten zum Exportieren');
    return;
  }

  try {
    showBanner('PDF wird erstellt...');

    const response = await fetch('/api/export/pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scanData: DATA })
    });

    if (!response.ok) throw new Error('PDF generation failed');

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-report-${Date.now()}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);

    showBanner('✅ PDF heruntergeladen!');
  } catch (error) {
    console.error('PDF export failed:', error);
    showBanner('❌ PDF-Export fehlgeschlagen');
  }
}

// Export Scan by ID
async function exportScanPDF(scanId) {
  try {
    showBanner('PDF wird erstellt...');

    const response = await fetch('/api/export/pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scanId })
    });

    if (!response.ok) throw new Error('PDF generation failed');

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-report-${scanId}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);

    showBanner('✅ PDF heruntergeladen!');
  } catch (error) {
    console.error('PDF export failed:', error);
    showBanner('❌ PDF-Export fehlgeschlagen');
  }
}

// Setup History Handlers
function setupHistoryHandlers() {
  const historyTab = document.querySelector('[data-tab="history"]');
  if (historyTab) {
    historyTab.addEventListener('click', () => loadHistory());
  }
}

// Create Charts with Chart.js
function createComplianceChart(marketingTags) {
  const canvas = document.getElementById('complianceChart');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');

  // Destroy existing chart
  if (chartInstances.compliance) {
    chartInstances.compliance.destroy();
  }

  const complianceData = {
    perfect: marketingTags.filter(t => t.compliance === 'perfect').length,
    good: marketingTags.filter(t => t.compliance === 'good').length,
    inconsistent: marketingTags.filter(t => t.compliance === 'inconsistent').length,
    bad: marketingTags.filter(t => t.compliance === 'bad').length,
    missing: marketingTags.filter(t => t.compliance === 'missing').length
  };

  chartInstances.compliance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Perfekt', 'Eingeschränkt', 'Uneinheitlich', 'Missachtet', 'Fehlt'],
      datasets: [{
        data: [complianceData.perfect, complianceData.good, complianceData.inconsistent, complianceData.bad, complianceData.missing],
        backgroundColor: ['#22c55e', '#a3e635', '#fbbf24', '#f87171', '#9ca3af']
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom' }
      }
    }
  });
}

function createIssuesChart(issues) {
  const canvas = document.getElementById('issuesChart');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');

  // Destroy existing chart
  if (chartInstances.issues) {
    chartInstances.issues.destroy();
  }

  const issuesData = {
    critical: issues.filter(i => i.priority === 'critical').length,
    high: issues.filter(i => i.priority === 'high').length,
    medium: issues.filter(i => i.priority === 'medium').length,
    low: issues.filter(i => i.priority === 'low').length
  };

  chartInstances.issues = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Kritisch', 'Hoch', 'Mittel', 'Niedrig'],
      datasets: [{
        label: 'Anzahl Probleme',
        data: [issuesData.critical, issuesData.high, issuesData.medium, issuesData.low],
        backgroundColor: ['#ef4444', '#f59e0b', '#fbbf24', '#a3e635']
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: { beginAtZero: true, ticks: { stepSize: 1 } }
      }
    }
  });
}

// Utility Functions
function getScoreClass(score) {
  if (score >= 80) return 'good';
  if (score >= 50) return 'medium';
  return 'bad';
}

function formatDate(dateString) {
  const date = new Date(dateString);
  const now = new Date();
  const diff = now - date;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (minutes < 60) return `vor ${minutes} Min.`;
  if (hours < 24) return `vor ${hours} Std.`;
  if (days < 7) return `vor ${days} Tagen`;
  return date.toLocaleDateString('de-DE');
}

// Initialize on page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initDashboard);
} else {
  initDashboard();
}
