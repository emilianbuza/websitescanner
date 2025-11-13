// pdfExport.js
// PDF-Report Generator mit PDFKit

import PDFDocument from 'pdfkit';
import { PassThrough } from 'stream';

export function generatePDF(scanData) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 50, bottom: 50, left: 50, right: 50 }
      });

      const stream = new PassThrough();
      const buffers = [];

      stream.on('data', chunk => buffers.push(chunk));
      stream.on('end', () => resolve(Buffer.concat(buffers)));
      stream.on('error', reject);

      doc.pipe(stream);

      // Header
      doc.fontSize(24).fillColor('#7c3aed').text('Website-Scanner Report', { align: 'center' });
      doc.moveDown(0.5);
      doc.fontSize(12).fillColor('#6b7280').text('Datenschutz & Marketing Compliance Check', { align: 'center' });
      doc.moveDown(1);

      // Meta info
      doc.fontSize(10).fillColor('#111827');
      doc.text(`URL: ${scanData.scannedUrl || 'N/A'}`, { continued: false });
      doc.text(`Datum: ${scanData.timestamp || new Date().toLocaleString('de-DE')}`, { continued: false });
      doc.text(`Version: ${scanData.version || '2.4.0'}`, { continued: false });
      doc.moveDown(1.5);

      // Divider
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#d1d5db').stroke();
      doc.moveDown(1);

      // Summary Section
      doc.fontSize(16).fillColor('#1f2937').text('Zusammenfassung', { underline: true });
      doc.moveDown(0.5);

      const summary = scanData.summary || {};
      const totalIssues = summary.totalIssues || 0;
      const criticalIssues = summary.highPriorityIssues || 0;
      const marketingTags = summary.marketingTags || [];

      doc.fontSize(11).fillColor('#111827');
      doc.text(`Gesamte Probleme: ${totalIssues}`, { continued: false });
      doc.text(`Kritische Probleme: ${criticalIssues}`, { continued: false });
      doc.text(`Marketing-Tags gefunden: ${marketingTags.length}`, { continued: false });
      doc.moveDown(1);

      // Risk Assessment
      let riskLevel = 'Niedrig';
      let riskColor = '#059669';

      if (criticalIssues > 2) {
        riskLevel = 'Hoch';
        riskColor = '#dc2626';
      } else if (criticalIssues > 0 || totalIssues > 5) {
        riskLevel = 'Mittel';
        riskColor = '#d97706';
      }

      doc.fontSize(12).fillColor(riskColor).text(`Risiko-Level: ${riskLevel}`, { continued: false });
      doc.moveDown(1.5);

      // Marketing Tags Compliance
      doc.fontSize(16).fillColor('#1f2937').text('Marketing-Tags & DSGVO-Compliance', { underline: true });
      doc.moveDown(0.5);

      if (marketingTags.length > 0) {
        doc.fontSize(10);
        marketingTags.forEach((tag, idx) => {
          const complianceIcon = {
            'perfect': '✅',
            'good': '🟡',
            'inconsistent': '🤔',
            'bad': '🚨',
            'missing': '❌'
          }[tag.compliance] || '–';

          doc.fillColor('#111827').text(`${idx + 1}. ${complianceIcon} ${tag.name}`, { continued: false });
          doc.fontSize(9).fillColor('#6b7280');
          doc.text(`   Compliance: ${tag.compliance || 'unknown'}`, { continued: false });
          doc.text(`   DSGVO-Risiko: ${tag.gdprRisk || 'unknown'}`, { continued: false });
          doc.text(`   Impact: ${tag.impact || 'N/A'}`, { continued: false });
          doc.moveDown(0.3);
        });
      } else {
        doc.fontSize(10).fillColor('#6b7280').text('Keine Marketing-Tags erkannt.', { continued: false });
      }

      doc.moveDown(1);

      // Add new page for details if needed
      if (doc.y > 650) doc.addPage();

      // Critical Issues
      const errors = scanData.details?.errors || [];
      const networkIssues = scanData.details?.networkIssues || [];
      const cspViolations = scanData.details?.cspViolations || [];

      if (errors.length > 0 || networkIssues.length > 0 || cspViolations.length > 0) {
        doc.fontSize(16).fillColor('#1f2937').text('Kritische Probleme & Lösungen', { underline: true });
        doc.moveDown(0.5);

        // Console Errors
        if (errors.length > 0) {
          doc.fontSize(12).fillColor('#dc2626').text('JavaScript-Fehler:', { continued: false });
          doc.moveDown(0.3);
          errors.slice(0, 5).forEach((err, idx) => {
            doc.fontSize(9).fillColor('#111827').text(`${idx + 1}. ${err.message?.substring(0, 80)}...`, { continued: false });
            if (err.translation) {
              doc.fillColor('#6b7280').text(`   ${err.translation}`, { continued: false });
            }
            if (err.techFix) {
              doc.fillColor('#059669').text(`   Lösung: ${err.techFix.substring(0, 80)}...`, { continued: false });
            }
            doc.moveDown(0.2);
          });
          doc.moveDown(0.5);
        }

        // Network Issues
        if (networkIssues.length > 0) {
          doc.fontSize(12).fillColor('#dc2626').text('Netzwerk-Probleme:', { continued: false });
          doc.moveDown(0.3);
          networkIssues.slice(0, 5).forEach((issue, idx) => {
            const host = tryGetHost(issue.url);
            doc.fontSize(9).fillColor('#111827').text(`${idx + 1}. ${host}`, { continued: false });
            if (issue.translation) {
              doc.fillColor('#6b7280').text(`   ${issue.translation}`, { continued: false });
            }
            doc.moveDown(0.2);
          });
          doc.moveDown(0.5);
        }

        // CSP Violations
        if (cspViolations.length > 0) {
          doc.fontSize(12).fillColor('#dc2626').text('Sicherheitsrichtlinien-Verstöße:', { continued: false });
          doc.moveDown(0.3);
          cspViolations.slice(0, 5).forEach((csp, idx) => {
            doc.fontSize(9).fillColor('#111827').text(`${idx + 1}. ${csp.message?.substring(0, 80)}...`, { continued: false });
            if (csp.techFix) {
              doc.fillColor('#059669').text(`   Lösung: ${csp.techFix.substring(0, 80)}...`, { continued: false });
            }
            doc.moveDown(0.2);
          });
        }
      }

      // Footer
      doc.fontSize(8).fillColor('#9ca3af');
      const pageCount = doc.bufferedPageRange().count;
      for (let i = 0; i < pageCount; i++) {
        doc.switchToPage(i);
        doc.text(
          `Seite ${i + 1} von ${pageCount} • Generiert am ${new Date().toLocaleString('de-DE')} • Website-Scanner v${scanData.version || '2.4.0'}`,
          50,
          doc.page.height - 30,
          { align: 'center' }
        );
      }

      doc.end();

    } catch (error) {
      reject(error);
    }
  });
}

function tryGetHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url.substring(0, 50);
  }
}
