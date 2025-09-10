// reportFormatter.js
// Wandelt Findings in managerfreundliche Blöcke um.

const FUNDORT_BAUSTEIN = `Sie finden den Fehler in der Browser-Entwicklerkonsole (Chrome oder Firefox):
1) Rechtsklick auf die Seite → „Untersuchen“ auswählen.
2) Oben im neuen Fenster den Tab „Konsole“ anklicken.
3) Dort ist die Meldung rot markiert (Fehler) oder gelb (Warnung).`;

function baseBlock() {
  return {
    problem: "",
    fundort: FUNDORT_BAUSTEIN,
    technischerFehler: "",
    auswirkung: "",
    loesung: "",
    beleg: {}
  };
}

export function formatReport(f) {
  const b = baseBlock();

  // Default-Beleg
  if (f.url) b.beleg.url = f.url;
  if (f.originalMessage) b.beleg.originalMessage = f.originalMessage;
  if (f.status) b.beleg.status = f.status;
  if (f.toolName) b.beleg.tool = f.toolName;
  if (f.session) b.beleg.session = f.session;
  if (f.evidence) b.beleg.evidence = f.evidence;

  switch (f.type) {
    case "csp":
      b.problem = `Die Website verhindert, dass ein Dienst Daten an seinen Server überträgt (${f.evidence?.directive ? `Regel: ${f.evidence.directive}` : "CSP-Blockade"}).`;
      b.technischerFehler = f.originalMessage || "CSP-Verletzung";
      b.auswirkung = "Der betroffene Dienst funktioniert nicht vollständig (z. B. Tests, Tracking oder Medien-Einbindung).";
      b.loesung = `Die IT muss die Sicherheitsrichtlinie („Content-Security-Policy“) so anpassen, dass die benötigte Domain erlaubt ist${f.url ? ` (z. B. ${f.url.split("/").slice(0,3).join("/")})` : ""}.`;
      return b;

    case "js_error":
      b.problem = "Auf der Website tritt ein JavaScript-Fehler auf.";
      b.technischerFehler = f.originalMessage;
      b.auswirkung = "Bestimmte Funktionen oder Messungen laufen fehlerhaft oder gar nicht.";
      b.loesung = "Die IT soll den Fehler im betroffenen Skript beheben (Fehlermeldung und Stacktrace in der Konsole prüfen).";
      return b;

    case "performance":
    case "performance_snapshot":
      b.problem = "Leistungs-Kennwerte weisen auf langsames Laden hin.";
      b.technischerFehler = f.originalMessage || JSON.stringify(f.evidence || {});
      b.auswirkung = "Langsame Seiten laden schlechtere Conversion-Raten und SEO-Signale.";
      b.loesung = "Blockierende Skripte reduzieren (async/defer), Third-Party-Skripte optimieren, Bilder/Fonts korrekt laden.";
      return b;

    case "network_error":
      b.problem = `Eine Verbindung zu einem externen Dienst scheitert${f.toolName ? ` (${f.toolName})` : ""}.`;
      b.technischerFehler = f.originalMessage;
      b.auswirkung = "Der Dienst kann keine Daten senden oder abrufen.";
      b.loesung = "IT prüfen: Ist die Domain erlaubt (CSP), erreichbar (Firewall/DNS) und korrekt eingebunden?";
      return b;

    case "tracking_hit":
      b.problem = `${f.toolName || "Ein Tracking-Dienst"} sendet Daten.`;
      b.technischerFehler = `HTTP-Status: ${f.status}. URL: ${f.url}`;
      b.auswirkung = "Hinweis: Dieser Dienst ist aktiv. Ohne gültige Einwilligung kann das DSGVO-relevant sein.";
      b.loesung = "Sicherstellen, dass der Dienst nur nach Einwilligung aktiv wird (Consent Mode/CMP) und datenschutzkonform konfiguriert ist.";
      return b;

    case "csp_header":
      b.problem = "Es ist eine Sicherheitsrichtlinie (CSP) gesetzt.";
      b.technischerFehler = f.evidence?.csp || "CSP vorhanden";
      b.auswirkung = "CSP schützt, kann aber Dienste blockieren, wenn Domains fehlen.";
      b.loesung = "Nur erforderliche Domains gezielt whitelisten; überbreite Wildcards vermeiden.";
      return b;

    case "cookies_snapshot":
      b.problem = "Es wurden Cookies gesetzt.";
      b.technischerFehler = `Anzahl Cookies: ${f.evidence?.count ?? "unbekannt"}`;
      b.auswirkung = "Tracking-/Marketing-Cookies vor Einwilligung sind DSGVO-relevant.";
      b.loesung = "Cookies nur nach Einwilligung setzen; Flags Secure/SameSite korrekt konfigurieren.";
      return b;

    case "storage_snapshot":
      b.problem = "Es gibt Einträge im Browser-Speicher (Web Storage / IndexedDB).";
      b.technischerFehler = `localStorage: ${f.evidence?.localCount ?? 0}, sessionStorage: ${f.evidence?.sessionCount ?? 0}, IndexedDBs: ${f.evidence?.idbCount ?? 0}`;
      b.auswirkung = "IDs im Storage ohne Einwilligung sind datenschutzrelevant.";
      b.loesung = "Speichern nur nach Einwilligung; Storage beim Reject löschen.";
      return b;

    case "script_present":
      b.problem = `${f.toolName || "Ein Tool"} ist eingebunden.`;
      b.technischerFehler = f.url || "Script eingebunden";
      b.auswirkung = "Das Tool kann Daten erfassen, wenn es aktiviert wird.";
      b.loesung = "Sicherstellen, dass Aktivierung/Trigger an Einwilligung gekoppelt ist.";
      return b;

    case "consent_status":
      b.problem = "Consent-Status geprüft.";
      b.technischerFehler = JSON.stringify(f.evidence || {});
      b.auswirkung = "Wenn TCF-API fehlt oder Status nie „granted“, feuern Tags nicht.";
      b.loesung = "CMP korrekt initialisieren; Events erst nach CMP-Ready auslösen.";
      return b;

    case "console_warning":
    default:
      b.problem = "Hinweis aus der Browser-Konsole.";
      b.technischerFehler = f.originalMessage || "Konsoleintrag";
      b.auswirkung = "Kann auf fehlerhafte Einbindung oder Blockaden hinweisen.";
      b.loesung = "Eintrag prüfen und ggf. Ursache beheben.";
      return b;
  }
}
