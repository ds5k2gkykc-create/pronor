# Bedienungsanleitung – finance-decision-system

Diese Anleitung zeigt, wie du das System als Pilotkunde nutzt: vom Login bis zum Export von PDF/DATEV.

## 1) Voraussetzungen

## Navigation (neues Mehrseiten-Layout)

Oben im Dashboard findest du Tabs:

- **Dashboard**: KPIs & Übersicht
- **Benutzer**: User-CRUD & Passwort-Reset
- **Anlagen & Prüfpläne**: Stammdaten
- **Prüfungen & Rechnungen**: operative Erfassung
- **Import/Export**: CSV, DATEV, Zahlung, Reminder
- **Hilfe**: Ablauf und Kontext

Jeder Bereich enthält einen **ℹ️ Info-Button**, der erklärt, was du dort machst und warum.


- Python 3.10+
- Projekt lokal ausgecheckt

## 2) Anwendung starten

```bash
python app.py
```

Dann im Browser öffnen:

- `http://localhost:8000`

## 3) Erster Login (Tenant anlegen)

Auf der Login-Seite ausfüllen:

- `tenant` (z. B. `muster-gmbh`)
- `user_id` (z. B. `admin1`)
- `role` = `admin`
- `password`
- optional `otp` (wenn 2FA-Secret gesetzt ist)

Beim ersten Login eines neuen Tenants wird der erste Benutzer registriert.

## 4) Benutzerverwaltung (nur Admin)

Im Bereich **User CRUD (Admin)**:

- **Create**: neuen Benutzer anlegen (`user_id`, `name`, `role`, `email`, Passwort, optional OTP-Secret)
- **Passwort Reset**: Passwort eines Users ändern
- **User löschen**: Benutzer entfernen

## 5) Anlagen und Prüfpläne anlegen

Im Bereich **Asset + Plan**:

- Asset-Daten erfassen (`asset_id`, Name, Seriennummer, Standort, Typ)
- dazugehörigen Prüfplan anlegen (`plan_id`, Regelwerk, Intervall in Tagen)

## 6) Prüfprotokoll + Rechnung erfassen

Im Bereich **Record + Invoice**:

- Prüfdaten eintragen (`record_id`, `plan_id`, `inspector_id`, Ergebnis, Feststellungen)
- Rechnungsdaten eintragen (`invoice_id`, Kunde, Preis)

Hinweis: Die Rechnung wird nur erzeugt, wenn ein Admin diese Aktion ausführt (RBAC).

## 7) CSV-Import (nur Admin)

Im Bereich **CSV Import (Admin)**:

- `kind = assets` oder `kind = plans`
- CSV in das Textfeld einfügen
- Import starten

### CSV-Beispiel Assets

```csv
asset_id,name,serial_number,location,asset_type
a1,Schaltschrank A,SN-001,Werk 1,Elektroanlage
```

### CSV-Beispiel Plans

```csv
plan_id,asset_id,regulation,interval_days
p1,a1,DGUV V3,180
```

## 8) Rechnungszahlung buchen (nur Admin)

Im Bereich **Invoice Payment (Admin)**:

- `invoice_id`
- Zahlungsbetrag

Das System aktualisiert den Rechnungsstatus automatisch:

- `offen`
- `teilbezahlt`
- `bezahlt`
- `ueberfaellig`

## 9) Exporte

### PDF-Report

- In der Protokolltabelle auf **PDF** klicken
- Export über Endpoint: `/export-record-pdf?record_id=<id>`

### DATEV-Export

- Link **DATEV Export** im Dashboard nutzen
- Export über Endpoint: `/export-datev`

## 10) Reminder auslösen

Im Bereich **Reminder**:

- Button **Eskalations-Mail senden** ausführen

Versandverhalten:

- wenn `data/smtp.host` existiert → SMTP-Versand
- sonst Fallback in `data/outbox/smtp-fallback.log`

## 11) API-Nutzung (mobile/offline)

### 11.1 JWT holen

`POST /api/v1/login` mit JSON:

```json
{
  "tenant": "muster-gmbh",
  "user_id": "admin1",
  "role": "admin",
  "password": "dein-passwort",
  "otp": "optional"
}
```

Antwort enthält `token`.

### 11.2 Dashboard per API

`GET /api/v1/dashboard` mit Header:

- `Authorization: Bearer <token>`

### 11.3 Offline-Sync

`POST /api/v1/sync` mit Header:

- `Authorization: Bearer <token>`

Body: Liste von Records inkl. `updated_at`.

Konfliktauflösung:

- `created`: neuer Record
- `updated`: vorhandener Record überschrieben (neuere Version)
- `ignored`: vorhandener Record bleibt erhalten (ältere Version)

## 12) Logs & Datenablage

- Tenant-Daten: `data/<tenant>.json`
- Benutzer/Auth: `data/auth.json`
- Audit-Log: `data/audit/<tenant>.log`
- Mail-Fallback: `data/outbox/smtp-fallback.log`

## 13) Typische Fehlerbehebung

- **403 Forbidden**: Aktion ist Admin-only.
- **401 API**: Token fehlt/abgelaufen/ungültig.
- **Login schlägt fehl**: Rolle, Passwort oder optional OTP prüfen.
- **Sync ignoriert Datensatz**: `updated_at` ist älter als bereits gespeicherte Version.