# finance-decision-system

Pilotfähiges MVP für **Prüfpflicht → Nachweis → Abrechnung** mit Mandantenfähigkeit.

## Neu umgesetzt (zusätzliche Schritte)

- Mehrseiten-Dashboard (Tabs) statt Ein-Seiten-Formular.
- Live-Dashboard mit Auto-Refresh (10 Sekunden) für KPIs und Fälligkeiten.
- Ampelsystem für Prüf-Fälligkeiten (rot/gelb/grün) direkt im Dashboard.
- Neuer AI-Assistent-Tab für Fragen zu Fälligkeiten, offenen Rechnungen und empfohlenen nächsten Schritten.
- AI kann per Kurzbefehlen direkt Aktionen ausführen (Anlage/Prüfplan/Nutzer anlegen, Batch-Prüfungen erzeugen).
- AI kann zusätzlich Zahlungen buchen (`zahlung:invoice_id|Betrag`) für schnelleren Rechnungsabschluss.
- Dashboard mit relevanten Diagrammen (Fälligkeits- und Rechnungsstatus) plus Live-Update.
- Automatischer Bereich für aktuelle regulatorische/bürokratische Updates (mit robustem Fallback bei Verbindungsproblemen).
- Besseres UX-Feedback mit Erfolgs-/Fehlerhinweisen nach Aktionen und Login.
- Neue Seite **Automationen** mit Auto-Terminierung/Routenplanung, Auto-Angebot, Mahnlogik, No-Show-Kaskade, Monatsreport und Management-Report.
- Compliance-Erweiterungen: Pflichtfeld-/Plausibilitätsregeln je Vorschrift, Risiko-Score, „Erstprüfung vergessen“-Erkennung.
- Kundenportal-Light mit Freigaben + Nachweisfoto und Maßnahmenplan-Datenbasis.
- AI-Workflows erweitert: `komplettauftrag`, `massnahmen`, `abrechnungsvorschlag`, `foto`.
- Beschriftete Eingabefelder inkl. Hinweise, Platzhalter und Info-Boxen je Aufgabe.
- Überarbeitetes modernes UI-Design mit klarer Navigation und Hilfebereich.
- Schnellfunktion im Dashboard: Demo-Anlage + Prüfplan automatisch erzeugen.
- Harte Benutzerverwaltung pro Tenant: User-CRUD, Passwort-Reset, optionale 2FA (OTP-Secret-basiert).
- Echte Mail-Integration via SMTP (`data/smtp.host`) mit Fallback-Outbox.
- Verbesserter PDF-Report mit strukturiertem Inhalt (Logo-Platzhalter, Mängelliste, Signatur-/Footer-Bereich).
- API-Auth mit JWT (`/api/v1/login`) und versionierte REST-API (`/api/v1/dashboard`, `/api/v1/sync`).
- Offline-Sync Konfliktauflösung über `updated_at` und Merge-Strategie (create/update/ignore).
- Weiterhin: RBAC, Audit-Logs, DATEV-Export, Rechnungsstatus-Workflow.

## Start

```bash
python app.py
```

Dann öffnen: `http://localhost:8000`

## Tests

```bash
pytest -q
```


## Bedienungsanleitung

- Siehe `BEDIENUNGSANLEITUNG.md` für Schritt-für-Schritt Nutzung.

## Priorisierte Roadmap

### Phase 1 (2–3 Wochen)
- Auto-Angebot aus Fälligkeiten
- Auto-Mahnlogik + Wochenreport per Mail
- AI-Workflow „Komplettauftrag anlegen"

### Phase 2 (4–6 Wochen)
- Maßnahmenplan aus Mängeln
- Kundenportal mit Status + Nachweis
- Routenplanung Light

### Phase 3 (6–10 Wochen)
- Risiko-Score + Haftungs-Dashboard
- Kosten-von-Nicht-Compliance Rechner
- Branchenpakete (Elektro, Hebezeuge, Maschinen)