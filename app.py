from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import smtplib
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from html import escape
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from sys import platform
from urllib import error, request
from urllib.parse import parse_qs, urlencode, urlparse

from executive_concept_mvp import (
    Asset,
    InspectionPlan,
    InspectionRecord,
    Role,
    TenantStorage,
    User,
)

storage = TenantStorage()
AUTH_FILE = Path("data/auth.json")
AUDIT_DIR = Path("data/audit")
OUTBOX_DIR = Path("data/outbox")
REG_UPDATES_FILE = Path("data/regulatory_updates.json")
SCHEDULE_DIR = Path("data/schedules")
OFFERS_DIR = Path("data/offers")
TASKS_DIR = Path("data/tasks")
PORTAL_DIR = Path("data/portal")
REPORTS_DIR = Path("data/reports")
CONTRACTS_DIR = Path("data/contracts")
SUBSCRIPTIONS_DIR = Path("data/subscriptions")
TEMPLATES_DIR = Path("data/templates")
EXPORTS_DIR = Path("data/exports")
DIFF_DIR = Path("data/diffs")
REGULATORY_SOURCES = [
    "https://www.bmas.de/DE/Service/Presse/Pressemitteilungen/rss.xml",
    "https://www.dguv.de/de/mediencenter/rss/index.jsp",
]
SESSIONS: dict[str, dict[str, str]] = {}
JWT_SECRET = (
    Path("data/jwt.secret").read_text().strip()
    if Path("data/jwt.secret").exists()
    else "dev-secret"
)

ROLE_LABELS = {
    "owner": "Owner/Admin",
    "admin": "Owner/Admin",
    "disposition": "Disposition",
    "pruefer": "Prüfer",
    "buchhaltung": "Buchhaltung",
    "kunde": "Kunde",
}

CAPABILITIES = {
    "owner": {"manage_users", "plan", "inspect", "billing", "automation", "ai_use", "ai_execute", "import_export", "view_all"},
    "admin": {"manage_users", "plan", "inspect", "billing", "automation", "ai_use", "ai_execute", "import_export", "view_all"},
    "disposition": {"plan", "automation", "ai_use", "view_all"},
    "pruefer": {"inspect", "ai_use", "view_all"},
    "buchhaltung": {"billing", "import_export", "ai_use", "view_all"},
    "kunde": {"ai_use"},
}
AI_ACTION_PREFIXES = {
    "komplettauftrag",
    "qualitaetscheck",
    "anlage",
    "pruefplan",
    "nutzer",
    "batchpruefung",
    "zahlung",
    "massnahmen",
    "abrechnungsvorschlag",
    "foto",
}

def has_capability(role: str, capability: str) -> bool:
    return capability in CAPABILITIES.get(role, set())


def to_domain_role(role: str) -> Role:
    if role == "pruefer":
        return Role.INSPECTOR
    if role == "kunde":
        return Role.CUSTOMER
    return Role.ADMIN


# ---------- Helpers ----------
def hash_password(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_auth() -> dict:
    if not AUTH_FILE.exists():
        return {}
    return json.loads(AUTH_FILE.read_text(encoding="utf-8"))


def save_auth(auth: dict) -> None:
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(json.dumps(auth, indent=2), encoding="utf-8")


def parse_csv_rows(text: str) -> list[dict[str, str]]:
    return [dict(r) for r in csv.DictReader(io.StringIO(text.strip()))]


def write_audit(tenant: str, actor: str, role: str, action: str, details: dict) -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    line = {
        "ts": datetime.utcnow().isoformat(),
        "actor": actor,
        "role": role,
        "action": action,
        "details": details,
    }
    with (AUDIT_DIR / f"{tenant}.log").open("a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sign_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


def verify_jwt(token: str) -> dict | None:
    try:
        h, p, s = token.split(".")
        expected = b64url(
            hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(s, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(p + "=="))
        if int(payload.get("exp", 0)) < int(datetime.utcnow().timestamp()):
            return None
        return payload
    except Exception:
        return None


def maybe_send_email(recipient: str, subject: str, body: str) -> None:
    host = (
        Path("data/smtp.host").read_text().strip()
        if Path("data/smtp.host").exists()
        else ""
    )
    if host:
        msg = EmailMessage()
        msg["From"] = "noreply@finance-decision.local"
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, 25, timeout=5) as smtp:
            smtp.send_message(msg)
    else:
        OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
        with (OUTBOX_DIR / "smtp-fallback.log").open("a", encoding="utf-8") as f:
            f.write(json.dumps({"to": recipient, "subject": subject, "body": body}) + "\n")


def send_escalation_emails(tenant: str, platform) -> int:
    reminders = platform.escalation_reminders()
    if not reminders:
        return 0
    recipients = [u.email for u in platform.users.values() if u.email]
    if not recipients:
        recipients = [f"compliance@{tenant}.local"]
    sent = 0
    for reminder in reminders:
        for recipient in recipients:
            maybe_send_email(recipient, f"[Reminder] {reminder['level']}", reminder["message"])
            sent += 1
    return sent


def build_ai_answer(question: str, platform) -> str:
    q = question.strip().lower()
    d = platform.dashboard()
    due = d.get("due_inspections", [])

    if any(k in q for k in ["fällig", "faellig", "prüfung", "pruefung", "nächste"]):
        if not due:
            return "Aktuell sind keine Prüfpläne vorhanden. Lege zuerst Anlage + Prüfplan an."
        top = due[:3]
        readable = ", ".join(
            f"{item['asset']} ({item['due_date']}, {item['state']})" for item in top
        )
        return f"Nächste Prüfungen: {readable}."

    if any(k in q for k in ["rechnung", "offen", "umsatz", "zahlung"]):
        return (
            f"Es gibt aktuell {d['open_invoices']} offene Rechnungen mit "
            f"{d['open_revenue_eur']:.2f} € offenem Betrag."
        )

    if any(k in q for k in ["start", "hilfe", "wie", "was tun"]):
        return (
            "Empfohlener Ablauf: 1) Benutzer anlegen, 2) Anlage + Prüfplan anlegen, "
            "3) Prüfung erfassen, 4) Rechnung erzeugen, 5) PDF/DATEV exportieren."
        )

    if any(k in q for k in ["risiko", "haftung", "rote liste", "kritisch"]):
        risk = build_risk_snapshot(platform)
        return (
            f"Risiko-Score: {risk['risk_score']} | Überfällig: {risk['overdue_due']} | "
            f"Kritisch in 7 Tagen: {risk['critical_next_7_days']} | Erstprüfung fehlt: {len(risk['missing_initial'])}."
        )

    if any(k in q for k in ["nichtstun", "kosten", "verlust"]):
        return f"Geschätzte Kosten von Nichtstun: {cost_of_inaction(platform):.2f} € (überfällige Forderungen + Compliance-Risiko)."

    if any(k in q for k in ["briefing", "heute", "today"]):
        risk = build_risk_snapshot(platform)
        d = platform.dashboard()
        return (
            f"Today Briefing: Prüfungen heute/nah={len([x for x in d['due_inspections'] if x['state'] in ['rot','gelb']])}, "
            f"kritisch={risk['overdue_due']}, offene Rechnungen={d['open_invoices']}, Risiko-Score={risk['risk_score']}."
        )

    if any(k in q for k in ["naechste aktion", "nächste aktion", "next best"]):
        return "Nächste beste Aktion: Admin=Automationen>Auto-Angebot, Prüfer=heutige Route bearbeiten, Kunde=Portal-Freigaben prüfen."

    return (
        "Ich kann dir zu Prüf-Fälligkeiten, offenen Rechnungen, Startschritten und Exporten helfen. "
        "Frage z. B.: 'Welche Prüfungen sind als nächstes fällig?'"
    )


def execute_ai_action(question: str, platform, auth_data: dict, tenant: str, id_builder) -> tuple[str, bool]:
    cleaned = question.strip()
    lower = cleaned.lower()

    if lower.startswith("komplettauftrag") and ":" not in lower:
        return "Ich brauche Details: komplettauftrag:Kunde|Standort|AnzahlAssets|Intervall|Pruefer", False

    if lower.startswith("qualitaetscheck:"):
        try:
            plan_id, measurement, attachment, signature = [p.strip() for p in cleaned.split(":", 1)[1].split("|")]
        except ValueError:
            return "Formatfehler. Nutze: qualitaetscheck:plan_id|messwert|anhang|signatur", False
        plan = platform.plans.get(plan_id)
        if not plan:
            return "Prüfplan nicht gefunden.", False
        issues = []
        if "DGUV" in plan.regulation and len(measurement) < 2:
            issues.append("Messwert fehlt")
        if "TRBS" in plan.regulation and len(attachment) < 3:
            issues.append("Anhang fehlt")
        if len(signature) < 2:
            issues.append("Signatur fehlt")
        if issues:
            return "Qualitätsprüfung: " + ", ".join(issues), False
        return "Qualitätsprüfung bestanden.", False

    if lower.startswith("anlage:"):
        try:
            name, location, asset_type = [p.strip() for p in cleaned.split(":", 1)[1].split("|")]
        except ValueError:
            return "Formatfehler. Nutze: anlage:Name|Standort|Typ", False
        asset_id = id_builder("a", platform.assets)
        platform.add_asset(Asset(asset_id, name, f"SN-{asset_id}", location, asset_type))
        return f"Anlage '{name}' wurde als {asset_id} angelegt.", True

    if lower.startswith("pruefplan:"):
        try:
            asset_id, regulation, interval_days = [p.strip() for p in cleaned.split(":", 1)[1].split("|")]
            interval = int(interval_days)
        except ValueError:
            return "Formatfehler. Nutze: pruefplan:asset_id|Regelwerk|IntervallTage", False
        if asset_id not in platform.assets:
            return f"Asset '{asset_id}' wurde nicht gefunden.", False
        plan_id = id_builder("p", platform.plans)
        platform.add_plan(InspectionPlan(plan_id, asset_id, regulation, interval))
        return f"Prüfplan {plan_id} für Asset {asset_id} wurde angelegt.", True

    if lower.startswith("nutzer:"):
        try:
            user_id, name, role, email = [p.strip() for p in cleaned.split(":", 1)[1].split("|")]
        except ValueError:
            return "Formatfehler. Nutze: nutzer:user_id|Name|admin/pruefer/kunde|email", False
        if role not in {"owner", "admin", "disposition", "pruefer", "buchhaltung", "kunde"}:
            return "Rolle muss owner/admin/disposition/pruefer/buchhaltung/kunde sein.", False
        users = {u["user_id"]: u for u in auth_data.setdefault(tenant, {"users": []})["users"]}
        users[user_id] = {
            "user_id": user_id,
            "name": name,
            "role": role,
            "email": email,
            "password_hash": hash_password("start123"),
            "otp_secret": "",
        }
        auth_data[tenant]["users"] = list(users.values())
        platform.add_user(User(user_id, name, to_domain_role(role), email))
        return f"Nutzer {user_id} angelegt. Startpasswort ist 'start123'.", True

    if lower.startswith("batchpruefung:"):
        try:
            inspector_id, customer, price = [p.strip() for p in cleaned.split(":", 1)[1].split("|")]
            price_value = float(price)
        except ValueError:
            return "Formatfehler. Nutze: batchpruefung:inspector_id|Kunde|Preis", False
        if inspector_id not in platform.users:
            return f"Prüfer {inspector_id} existiert nicht.", False
        if not platform.plans:
            return "Keine Prüfpläne vorhanden.", False
        created_records = []
        for plan in platform.plans.values():
            record_id = id_builder("r", platform.records)
            platform.record_inspection(
                InspectionRecord(record_id, plan.plan_id, inspector_id, date.today(), "bestanden", "Automatisch durch AI erfasst")
            )
            created_records.append(record_id)
        invoice_id = id_builder("i", platform.invoices)
        platform.create_invoice(invoice_id, customer, created_records, price_value)
        return f"Batch abgeschlossen: {len(created_records)} Prüfungen + Rechnung {invoice_id} erstellt.", True

    if lower.startswith("zahlung:"):
        try:
            invoice_id, amount = [p.strip() for p in cleaned.split(":", 1)[1].split("|")]
            amount_value = float(amount)
        except ValueError:
            return "Formatfehler. Nutze: zahlung:invoice_id|Betrag", False
        if invoice_id not in platform.invoices:
            return f"Rechnung {invoice_id} wurde nicht gefunden.", False
        inv = platform.update_invoice_payment(invoice_id, amount_value)
        return f"Zahlung gebucht. Status von {invoice_id}: {inv.status.value}.", True

    if lower.startswith("komplettauftrag:"):
        try:
            customer, location, amount_assets, interval_days, inspector = [
                p.strip() for p in cleaned.split(":", 1)[1].split("|")
            ]
            amount = max(1, int(amount_assets))
            interval = max(30, int(interval_days))
        except ValueError:
            return "Formatfehler. Nutze: komplettauftrag:Kunde|Standort|AnzahlAssets|Intervall|Pruefer", False
        if inspector not in platform.users:
            return f"Prüfer {inspector} nicht gefunden.", False
        created = []
        for idx in range(amount):
            asset_id = id_builder("a", platform.assets)
            plan_id = id_builder("p", platform.plans)
            platform.add_asset(Asset(asset_id, f"{customer}-Asset-{idx+1}", f"SN-{asset_id}", location, "Elektroanlage"))
            platform.add_plan(InspectionPlan(plan_id, asset_id, "DGUV V3", interval))
            created.append((asset_id, plan_id))
        route = generate_route_plan(platform)
        save_json_file(SCHEDULE_DIR / f"{tenant}.json", {"created_at": datetime.utcnow().isoformat(), "route": route})
        return f"Komplettauftrag angelegt: {len(created)} Assets + Prüfpläne inkl. erster Tourplanung.", True

    if lower.startswith("massnahmen:"):
        try:
            record_id, owner = [p.strip() for p in cleaned.split(":", 1)[1].split("|")]
        except ValueError:
            return "Formatfehler. Nutze: massnahmen:record_id|verantwortlicher", False
        record = platform.records.get(record_id)
        if not record:
            return f"Record {record_id} wurde nicht gefunden.", False
        findings = [f.strip() for f in record.findings.replace(";", ",").split(",") if f.strip()]
        tasks = load_json_file(TASKS_DIR / f"{tenant}.json", [])
        for idx, finding in enumerate(findings or ["Allgemeine Nachkontrolle"]):
            due = date.today() + timedelta(days=3 + idx * 2)
            tasks.append(
                {
                    "task_id": f"t{len(tasks)+1}",
                    "record_id": record_id,
                    "owner": owner,
                    "priority": "hoch" if idx == 0 else "mittel",
                    "title": finding,
                    "due_date": due.isoformat(),
                    "status": "offen",
                }
            )
        save_json_file(TASKS_DIR / f"{tenant}.json", tasks)
        return f"Maßnahmenplan mit {len(findings) or 1} Aufgaben erstellt.", True

    if lower.startswith("abrechnungsvorschlag:"):
        try:
            customer, price = [p.strip() for p in cleaned.split(":", 1)[1].split("|")]
            price_value = float(price)
        except ValueError:
            return "Formatfehler. Nutze: abrechnungsvorschlag:Kunde|Preis", False
        unbilled = [r.record_id for r in platform.records.values() if not any(r.record_id in inv.source_record_ids for inv in platform.invoices.values())]
        if not unbilled:
            return "Kein abrechenbarer Prüfdatensatz gefunden.", False
        invoice_id = id_builder("i", platform.invoices)
        platform.create_invoice(invoice_id, customer, unbilled, price_value)
        return f"Abrechnungsvorschlag umgesetzt: Rechnung {invoice_id} mit {len(unbilled)} Positionen.", True

    if lower.startswith("foto:"):
        try:
            photo_ref, location = [p.strip() for p in cleaned.split(":", 1)[1].split("|")]
        except ValueError:
            return "Formatfehler. Nutze: foto:bildname.jpg|Standort", False
        asset_type, regulation = suggest_asset_from_photo(photo_ref)
        asset_id = id_builder("a", platform.assets)
        plan_id = id_builder("p", platform.plans)
        platform.add_asset(Asset(asset_id, f"Auto-{asset_type}", f"SN-{asset_id}", location, asset_type))
        platform.add_plan(InspectionPlan(plan_id, asset_id, regulation, 180))
        return f"Foto-Vorschlag umgesetzt: {asset_type} + Plan {plan_id} ({regulation}).", True

    return "", False


def get_regulatory_updates() -> list[dict[str, str]]:
    now = datetime.utcnow()
    if REG_UPDATES_FILE.exists():
        cached = json.loads(REG_UPDATES_FILE.read_text(encoding="utf-8"))
        fetched_at = datetime.fromisoformat(cached.get("fetched_at", now.isoformat()))
        if (now - fetched_at).total_seconds() < 12 * 3600 and cached.get("items"):
            return cached["items"]

    updates: list[dict[str, str]] = []
    for source in REGULATORY_SOURCES:
        try:
            with request.urlopen(source, timeout=4) as response:
                payload = response.read().decode("utf-8", errors="ignore")
            for match in re.finditer(r"<item>.*?<title>(.*?)</title>.*?<pubDate>(.*?)</pubDate>", payload, re.S):
                title = re.sub(r"<.*?>", "", match.group(1)).strip()
                pub = re.sub(r"<.*?>", "", match.group(2)).strip()
                updates.append({"title": title, "published": pub, "source": source})
                if len(updates) >= 6:
                    break
        except (error.URLError, TimeoutError, ValueError):
            continue

    if not updates:
        updates = [
            {
                "title": "Keine Live-Änderung abrufbar – letzter Stand verwenden und regelmäßig prüfen.",
                "published": now.strftime("%Y-%m-%d %H:%M UTC"),
                "source": "local-fallback",
            }
        ]

    REG_UPDATES_FILE.parent.mkdir(parents=True, exist_ok=True)
    REG_UPDATES_FILE.write_text(
        json.dumps({"fetched_at": now.isoformat(), "items": updates}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return updates


def load_json_file(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def save_json_file(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_compliance_templates(tenant: str) -> dict[str, dict[str, str]]:
    raw = load_json_file(TEMPLATES_DIR / f"{tenant}.json", {})
    if isinstance(raw, dict):
        return raw
    return {}


def validate_template_requirements(tenant: str, customer: str, extra_value: str) -> tuple[bool, str]:
    templates = load_compliance_templates(tenant)
    key = customer.strip().lower()
    tpl = templates.get(key) or templates.get("default")
    if not tpl:
        return True, ""
    required_label = tpl.get("required_extra", "Zusatzfeld")
    if not extra_value.strip():
        return False, f"Template-Pflichtfeld fehlt: {required_label}"
    return True, required_label


def suggest_asset_from_photo(photo_ref: str) -> tuple[str, str]:
    ref = photo_ref.lower()
    if "kabel" in ref or "elektro" in ref or "schrank" in ref:
        return "Elektroanlage", "DGUV V3"
    if "kran" in ref or "haken" in ref or "lift" in ref:
        return "Hebezeug", "TRBS"
    if "druck" in ref or "kessel" in ref:
        return "Druckanlage", "TRBS"
    return "Maschine", "TRBS"


def generate_route_plan(platform) -> list[dict[str, str]]:
    inspectors = [u.user_id for u in platform.users.values() if u.role.value in {"pruefer", "admin"}]
    if not inspectors:
        inspectors = ["admin"]
    due = []
    today = date.today()
    for plan in platform.plans.values():
        due_date = plan.next_due_date()
        days = (due_date - today).days
        if days <= 30:
            asset = platform.assets[plan.asset_id]
            due.append((asset.location, due_date, plan.plan_id, asset.name))
    due.sort(key=lambda x: (x[0], x[1]))
    route = []
    for idx, item in enumerate(due):
        route.append(
            {
                "inspector": inspectors[idx % len(inspectors)],
                "location": item[0],
                "due_date": item[1].isoformat(),
                "plan_id": item[2],
                "asset": item[3],
            }
        )
    return route


def create_due_offer(platform, horizon_days: int = 30) -> dict:
    today = date.today()
    included = []
    for plan in platform.plans.values():
        due_date = plan.next_due_date()
        if (due_date - today).days <= horizon_days:
            asset = platform.assets[plan.asset_id]
            included.append({"plan_id": plan.plan_id, "asset": asset.name, "location": asset.location, "due_date": due_date.isoformat()})
    price = round(len(included) * 129.0, 2)
    return {
        "created_at": datetime.utcnow().isoformat(timespec="seconds"),
        "horizon_days": horizon_days,
        "count": len(included),
        "offer_total_eur": price,
        "items": included,
    }


def dunning_actions(platform) -> list[dict[str, str]]:
    actions = []
    today = date.today()
    for inv in platform.invoices.values():
        if inv.status.value == "bezahlt" or not inv.due_date:
            continue
        late_days = (today - inv.due_date).days
        if late_days <= 0:
            continue
        level = "Stufe 1" if late_days <= 7 else "Stufe 2" if late_days <= 21 else "Inkasso-Vorwarnung"
        actions.append({"invoice_id": inv.invoice_id, "customer": inv.customer, "late_days": str(late_days), "level": level})
    return actions


def build_risk_snapshot(platform) -> dict:
    dash = platform.dashboard()
    overdue = sum(1 for d in dash["due_inspections"] if d["state"] == "rot")
    yellow = sum(1 for d in dash["due_inspections"] if d["state"] == "gelb")
    overdue_invoices = sum(1 for inv in platform.invoices.values() if inv.status.value == "ueberfaellig")
    missing_initial = []
    for plan in platform.plans.values():
        if plan.last_inspection is None:
            asset = platform.assets[plan.asset_id]
            missing_initial.append({"asset": asset.name, "plan_id": plan.plan_id, "location": asset.location})
    risk_score = min(100, overdue * 20 + yellow * 8 + overdue_invoices * 15 + len(missing_initial) * 10)
    return {
        "risk_score": risk_score,
        "overdue_due": overdue,
        "critical_next_7_days": yellow,
        "overdue_invoices": overdue_invoices,
        "missing_initial": missing_initial,
    }


def monthly_customer_report(platform) -> dict:
    risk = build_risk_snapshot(platform)
    open_findings = [r for r in platform.records.values() if "mangel" in r.findings.lower()]
    return {
        "created_at": datetime.utcnow().isoformat(timespec="seconds"),
        "records": len(platform.records),
        "open_findings": len(open_findings),
        "open_invoices": sum(1 for inv in platform.invoices.values() if inv.status.value != "bezahlt"),
        "next_due": platform.dashboard()["due_inspections"][:10],
        "risk_score": risk["risk_score"],
    }


def cost_of_inaction(platform) -> float:
    overdue_revenue = sum(
        max(inv.amount_eur - inv.paid_amount_eur, 0)
        for inv in platform.invoices.values()
        if inv.status.value == "ueberfaellig"
    )
    overdue_due = sum(1 for item in platform.dashboard()["due_inspections"] if item["state"] == "rot")
    compliance_risk_estimate = overdue_due * 250.0
    return round(overdue_revenue + compliance_risk_estimate, 2)


def sla_monitor(platform, tenant: str) -> dict:
    contracts = load_json_file(CONTRACTS_DIR / f"{tenant}.json", {"sla_days": 14})
    sla_days = int(contracts.get("sla_days", 14))
    today = date.today()
    risky = 0
    breaches = 0
    for item in platform.dashboard()["due_inspections"]:
        due_date = date.fromisoformat(item["due_date"])
        delta = (due_date - today).days
        if delta <= 0:
            breaches += 1
        elif delta <= sla_days:
            risky += 1
    score = min(100, breaches * 20 + risky * 8)
    return {"sla_days": sla_days, "risky": risky, "breaches": breaches, "sla_risk_score": score}


def tenant_health_score(platform, tenant: str) -> int:
    risk = build_risk_snapshot(platform)
    dunning = len(dunning_actions(platform))
    tasks = len(load_json_file(TASKS_DIR / f"{tenant}.json", []))
    score = min(100, risk["risk_score"] + dunning * 4 + min(tasks, 20))
    return score


def lost_revenue_list(platform) -> list[dict[str, str]]:
    billed_records = {rid for inv in platform.invoices.values() for rid in inv.source_record_ids}
    out = []
    for item in platform.dashboard()["due_inspections"]:
        plan_id = item["plan_id"]
        has_record = any(r.plan_id == plan_id for r in platform.records.values())
        has_invoice = any((r.plan_id == plan_id and r.record_id in billed_records) for r in platform.records.values())
        if not has_record or not has_invoice:
            out.append({"plan_id": plan_id, "asset": item["asset"], "due_date": item["due_date"], "reason": "keine Rechnung" if has_record else "keine Prüfung"})
    return out


def explain_red_items(platform) -> list[dict[str, str]]:
    out = []
    today = date.today()
    for item in platform.dashboard()["due_inspections"]:
        if item["state"] != "rot":
            continue
        due = date.fromisoformat(item["due_date"])
        days = (today - due).days
        out.append({"asset": item["asset"], "reason": f"Überfällig seit {days} Tagen ({item['regulation']})"})
    return out


def recurring_invoice_run(platform, tenant: str) -> list[str]:
    subs = load_json_file(SUBSCRIPTIONS_DIR / f"{tenant}.json", [])
    created = []
    today = date.today()
    for sub in subs:
        next_run = date.fromisoformat(sub.get("next_run", today.isoformat()))
        if next_run > today:
            continue
        invoice_id = f"i{sub.get('customer','kunde').replace(' ','').lower()}-{today.isoformat()}"
        if invoice_id in platform.invoices:
            continue
        platform.invoices[invoice_id] = platform.create_invoice(invoice_id, sub.get("customer", "Kunde"), [], float(sub.get("amount", 0.0)))
        interval = int(sub.get("interval_days", 30))
        sub["next_run"] = (today + timedelta(days=interval)).isoformat()
        created.append(invoice_id)
    save_json_file(SUBSCRIPTIONS_DIR / f"{tenant}.json", subs)
    return created


def record_diff(tenant: str, record_id: str, before_text: str, after_text: str) -> None:
    history = load_json_file(DIFF_DIR / f"{tenant}.json", [])
    history.append({"ts": datetime.utcnow().isoformat(timespec="seconds"), "record_id": record_id, "before": before_text, "after": after_text})
    save_json_file(DIFF_DIR / f"{tenant}.json", history)


def render_pdf_report(record, tenant: str) -> bytes:
    lines = [
        "COMPLIANCE INSPECTION REPORT",
        f"Tenant: {tenant}",
        "Logo: [COMPANY LOGO]",
        f"Record ID: {record.record_id}",
        f"Plan ID: {record.plan_id}",
        f"Inspector: {record.inspector_id}",
        f"Date: {record.performed_on.isoformat()}",
        "Maengelliste:",
        f"- {record.findings}",
        "Digitale Unterschrift: hash-placeholder",
        "Footer: Seite 1/1",
    ]
    y = 800
    chunks = []
    for line in lines:
        safe = line.replace("(", "[").replace(")", "]")
        chunks.append(f"BT /F1 11 Tf 50 {y} Td ({safe}) Tj ET")
        y -= 20
    stream = "\n".join(chunks)
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
        f"5 0 obj << /Length {len(stream)} >> stream\n{stream}\nendstream endobj",
    ]
    out = "%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(out.encode("utf-8")))
        out += obj + "\n"
    xref = len(out.encode("utf-8"))
    out += f"xref\n0 {len(offsets)}\n0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n"
    out += f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    return out.encode("utf-8")


# ---------- UI ----------
def info_box(title: str, text: str) -> str:
    return f"<details class='info'><summary>ℹ️ {title}</summary><p>{text}</p></details>"


def label_input(label: str, name: str, placeholder: str = "", input_type: str = "text", value: str = "") -> str:
    return (
        "<div class='field'>"
        f"<label for='{name}'>{label}</label>"
        f"<input id='{name}' name='{name}' type='{input_type}' placeholder='{placeholder}' value='{value}' required/>"
        "</div>"
    )


def traffic_badge(state: str) -> str:
    colors = {"rot": "#d92d20", "gelb": "#f79009", "gruen": "#12b76a"}
    labels = {"rot": "Überfällig", "gelb": "Bald fällig", "gruen": "OK"}
    color = colors.get(state, "#667085")
    label = labels.get(state, state)
    return f"<span style='display:inline-flex;align-items:center;gap:.35rem'><span style='width:.62rem;height:.62rem;border-radius:999px;background:{color};display:inline-block'></span>{escape(label)}</span>"


def nav(active: str, role: str) -> str:
    items = [
        ("dashboard", "Dashboard", "view_all"),
        ("automation", "Automationen", "automation"),
        ("users", "Benutzer", "manage_users"),
        ("assets", "Anlagen & Prüfpläne", "plan"),
        ("records", "Prüfungen & Rechnungen", "inspect"),
        ("imports", "Import/Export", "import_export"),
        ("ai", "AI-Assistent", "ai_use"),
        ("help", "Hilfe", "ai_use"),
    ]
    links = []
    for key, label, cap in items:
        if not has_capability(role, cap):
            continue
        cls = "tab active" if key == active else "tab"
        links.append(f"<a class='{cls}' href='/?{urlencode({'page': key})}'>{label}</a>")
    return "".join(links)


def page(title: str, body: str, current_tab: str = "dashboard", show_logout: bool = True, role: str = "kunde") -> bytes:
    logout_html = ""
    if show_logout:
        logout_html = """
    <form method='post' action='/logout' style='display:block;margin:0'>
      <button class='secondary' type='submit'>Logout</button>
    </form>
"""
    html = f"""
<!doctype html>
<html lang='de'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>{title}</title>
<style>
:root {{ --bg:#f1f5f9; --card:#ffffff; --text:#0f172a; --muted:#64748b; --primary:#2563eb; --primary-2:#1d4ed8; --border:#e2e8f0; --ring:rgba(37,99,235,.18); }}
* {{ box-sizing: border-box; }}
body {{ margin:0; font-family: Inter, 'Segoe UI', Arial, sans-serif; background:radial-gradient(circle at 15% -20%, #dbeafe, transparent 40%), radial-gradient(circle at 85% -30%, #e0e7ff, transparent 34%), var(--bg); color:var(--text); }}
.wrapper {{ max-width:1240px; margin:0 auto; padding:1.2rem; }}
.header {{ display:flex; justify-content:space-between; align-items:center; gap:1rem; margin-bottom:1rem; padding:.9rem 1rem; background:rgba(255,255,255,.8); border:1px solid rgba(148,163,184,.22); border-radius:16px; backdrop-filter: blur(6px); }}
.brand {{ font-weight:800; font-size:1.22rem; letter-spacing:.2px; }}
.tabs {{ display:flex; gap:.55rem; flex-wrap:wrap; margin-bottom:1rem; }}
.tab {{ text-decoration:none; color:#0f172a; padding:.5rem .82rem; border:1px solid #dbe3ef; border-radius:12px; background:#fff; transition:all .18s ease; font-weight:600; }}
.tab:hover {{ transform:translateY(-1px); border-color:#bfdbfe; box-shadow:0 4px 14px rgba(37,99,235,.12); }}
.tab.active {{ background:linear-gradient(135deg,var(--primary),var(--primary-2)); color:#fff; border-color:transparent; box-shadow:0 8px 18px rgba(37,99,235,.35); }}
.card {{ background:var(--card); border:1px solid var(--border); border-radius:14px; padding:1rem; margin-bottom:1rem; box-shadow:0 8px 24px rgba(15,23,42,.06); opacity:0; transform:translateY(8px); animation:fadeInUp .32s ease forwards; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:.7rem; }}
.kpi {{ padding:.95rem; border-radius:12px; background:linear-gradient(145deg,#eff6ff,#dbeafe); border:1px solid #bfdbfe; color:#1e3a8a; }}
.kpi h3 {{ margin:.2rem 0 0 0; }}
form {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:.8rem; align-items:end; }}
.field {{ display:flex; flex-direction:column; gap:.3rem; }}
label {{ font-size:.88rem; color:#334155; font-weight:600; }}
input, select, textarea, button {{ padding:.66rem; border-radius:10px; border:1px solid #cbd5e1; font:inherit; }}
input:focus, select:focus, textarea:focus {{ outline:none; border-color:#60a5fa; box-shadow:0 0 0 4px var(--ring); }}
textarea {{ min-height:120px; }}
button {{ background:linear-gradient(135deg,var(--primary),var(--primary-2)); color:#fff; border:none; cursor:pointer; font-weight:600; transition:transform .14s ease, box-shadow .14s ease; }}
button:hover {{ transform:translateY(-1px); box-shadow:0 8px 18px rgba(37,99,235,.28); }}
button.secondary {{ background:#eef2ff; color:#1d4ed8; border:1px solid #c7d2fe; }}
.info {{ border:1px dashed #93c5fd; padding:.5rem .7rem; border-radius:10px; background:#eff6ff; }}
.info summary {{ cursor:pointer; font-weight:600; }}
.table-wrap {{ overflow:auto; }}
table {{ width:100%; border-collapse:collapse; }}
th, td {{ text-align:left; padding:.62rem; border-bottom:1px solid var(--border); white-space:nowrap; }}
th {{ font-size:.82rem; color:#475569; text-transform:uppercase; letter-spacing:.03em; }}
.muted {{ color:var(--muted); }}
.stack {{ display:grid; gap:1rem; }}
.answer {{ background:linear-gradient(180deg,#ffffff,#f8fafc); border:1px solid #e2e8f0; border-radius:12px; padding:.8rem; }}
.page-title {{ margin:.1rem 0 .6rem 0; }}
.chat {{ display:flex; flex-direction:column; gap:.6rem; }}
.bubble {{ max-width:78%; padding:.7rem .8rem; border-radius:12px; line-height:1.35; }}
.bubble.user {{ align-self:flex-end; background:#dbeafe; border:1px solid #93c5fd; }}
.bubble.ai {{ align-self:flex-start; background:#f8fafc; border:1px solid #cbd5e1; }}
.quick-actions {{ display:flex; gap:.5rem; flex-wrap:wrap; margin:.4rem 0 .8rem 0; }}
.quick-actions button {{ background:#eef2ff; color:#1e3a8a; border:1px solid #c7d2fe; }}
.kpi {{ transition:transform .25s ease, box-shadow .25s ease; }}
.table-wrap {{ transition:box-shadow .2s ease; }}
.table-wrap:hover {{ box-shadow:inset 0 0 0 1px #dbeafe; border-radius:8px; }}
.kpi.changed {{ transform:translateY(-2px) scale(1.02); box-shadow:0 8px 20px rgba(37,99,235,.20); }}
.row-enter {{ animation:rowIn .25s ease both; }}
@keyframes fadeInUp {{ from {{ opacity:0; transform:translateY(8px); }} to {{ opacity:1; transform:translateY(0); }} }}
@keyframes rowIn {{ from {{ opacity:.2; transform:translateX(-6px); }} to {{ opacity:1; transform:translateX(0); }} }}
@media (max-width: 760px) {{
  .wrapper {{ padding:.8rem; }}
  .header {{ padding:.7rem .8rem; }}
  .tabs {{ gap:.4rem; }}
  .tab {{ padding:.42rem .6rem; font-size:.9rem; }}
}}
</style>
</head>
<body>
<div class='wrapper'>
  <div class='header'>
    <div class='brand'>Finance Decision System</div>
    {logout_html}
  </div>
  <nav class='tabs'>{nav(current_tab, role)}</nav>
  {body}
</div>

<script>
(function(){{
  const cards = document.querySelectorAll('.card');
  cards.forEach((card, i) => {{ card.style.animationDelay = `${{Math.min(i*0.03,0.25)}}s`; }});
  document.querySelectorAll('a.tab').forEach(a => {{
    a.addEventListener('click', () => {{ document.body.style.opacity = '0.985'; }});
  }});
}})();
</script>

</body>
</html>
"""
    return html.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def next_id(self, prefix: str, existing: dict) -> str:
        idx = 1
        while f"{prefix}{idx}" in existing:
            idx += 1
        return f"{prefix}{idx}"

    def safe_form_value(self, form: dict, key: str) -> str:
        if key not in form or not form[key] or not form[key][0].strip():
            raise ValueError(f"Feld fehlt: {key}")
        return form[key][0].strip()

    def optional_form_value(self, form: dict, key: str, default: str = "") -> str:
        return form.get(key, [default])[0].strip()

    def redirect_with_message(self, text: str, kind: str = "ok", page_name: str | None = None) -> None:
        query = {"msg": text, "kind": kind}
        if page_name:
            query["page"] = page_name
        self.redirect(f"/?{urlencode(query)}")

    def current(self) -> dict:
        c = cookies.SimpleCookie(self.headers.get("Cookie"))
        token = c.get("session")
        return SESSIONS.get(token.value, {}) if token else {}

    def require_admin(self) -> bool:
        cur = self.current()
        return bool(cur and has_capability(cur.get("role", ""), "manage_users"))

    def require_capability(self, capability: str) -> bool:
        cur = self.current()
        return bool(cur and has_capability(cur.get("role", ""), capability))

    # ---------- GET ----------
    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/v1/dashboard":
            auth = self.headers.get("Authorization", "")
            payload = verify_jwt(auth.replace("Bearer ", "")) if auth.startswith("Bearer ") else None
            if not payload:
                self.send_error(401)
                return
            self.json_response(storage.load(payload["tenant"]).dashboard())
            return

        if parsed.path == "/api/live-dashboard":
            cur = self.current()
            if not cur:
                self.send_error(401)
                return
            platform = storage.load(cur["tenant"])
            d = platform.dashboard()
            sla = sla_monitor(platform, cur["tenant"])
            due_states = {"rot": 0, "gelb": 0, "gruen": 0}
            for item in d["due_inspections"]:
                due_states[item["state"]] = due_states.get(item["state"], 0) + 1
            invoice_states = {"offen": 0, "teilbezahlt": 0, "bezahlt": 0, "ueberfaellig": 0}
            for inv in platform.invoices.values():
                invoice_states[inv.status.value] = invoice_states.get(inv.status.value, 0) + 1
            self.json_response(
                {
                    **d,
                    "reminders": len(platform.escalation_reminders()),
                    "updated_at": datetime.utcnow().isoformat(timespec="seconds"),
                    "due_states": due_states,
                    "invoice_states": invoice_states,
                    "sla_risk_score": sla["sla_risk_score"],
                    "tenant_health": tenant_health_score(platform, cur["tenant"]),
                }
            )
            return

        if parsed.path == "/export-record-pdf":
            cur = self.current()
            if not cur:
                self.redirect("/")
                return
            record_id = parse_qs(parsed.query).get("record_id", [""])[0]
            platform = storage.load(cur["tenant"])
            record = platform.records.get(record_id)
            if not record:
                self.send_error(404)
                return
            payload = render_pdf_report(record, cur["tenant"])
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f"attachment; filename=report-{record_id}.pdf")
            self.end_headers()
            self.wfile.write(payload)
            return

        if parsed.path == "/export-datev":
            if not self.require_capability("import_export"):
                self.send_error(403)
                return
            cur = self.current()
            platform = storage.load(cur["tenant"])
            buf = io.StringIO()
            writer = csv.DictWriter(
                buf,
                fieldnames=["rechnung", "kunde", "betrag", "bezahlt", "status", "faellig"],
                delimiter=";",
            )
            writer.writeheader()
            writer.writerows(platform.datev_export_rows())
            data = buf.getvalue().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.end_headers()
            self.wfile.write(data)
            return

        if parsed.path != "/":
            self.send_error(404)
            return

        cur = self.current()
        if not cur:
            self.render_login()
            return

        platform = storage.load(cur["tenant"])
        query = parse_qs(parsed.query)
        tab = query.get("page", ["dashboard"])[0]
        auto_page = query.get("auto", ["overview"])[0]
        message = query.get("msg", [""])[0]
        kind = query.get("kind", ["ok"])[0]
        banner = ""
        if message:
            bg = "#dcfce7" if kind == "ok" else "#fee2e2"
            banner = f"<div class='card' style='background:{bg}'><b>{escape(message)}</b></div>"

        tab_caps = {
            "dashboard": "view_all",
            "automation": "automation",
            "users": "manage_users",
            "assets": "plan",
            "records": "inspect",
            "imports": "import_export",
            "ai": "ai_use",
            "help": "ai_use",
        }
        required_cap = tab_caps.get(tab, "view_all")
        if not has_capability(cur["role"], required_cap):
            tab = "dashboard"

        if tab == "users":
            self.respond(page("Benutzer", banner + self.users_page(cur, platform), "users", role=cur["role"]))
        elif tab == "automation":
            self.respond(page("Automationen", banner + self.automation_page(cur, platform, auto_page), "automation", role=cur["role"]))
        elif tab == "assets":
            self.respond(page("Anlagen", banner + self.assets_page(platform), "assets", role=cur["role"]))
        elif tab == "records":
            self.respond(page("Prüfungen", banner + self.records_page(cur, platform), "records", role=cur["role"]))
        elif tab == "imports":
            self.respond(page("Import/Export", banner + self.imports_page(cur), "imports", role=cur["role"]))
        elif tab == "ai":
            self.respond(page("AI-Assistent", banner + self.ai_page(cur, platform), "ai", role=cur["role"]))
        elif tab == "help":
            self.respond(page("Hilfe", banner + self.help_page(), "help", role=cur["role"]))
        else:
            self.respond(page("Dashboard", banner + self.dashboard_page(cur, platform), "dashboard", role=cur["role"]))

    def render_login(self) -> None:
        body = f"""
<div class='card'>
  <h2>Login / Registrierung</h2>
  {info_box('Warum?', 'Du meldest dich tenant-spezifisch an, damit Kundendaten getrennt bleiben.')}
  <form method='post' action='/login'>
    {label_input('Tenant (Firma)', 'tenant', 'z. B. muster-gmbh')}
    {label_input('Benutzer-ID', 'user_id', 'z. B. admin1')}
    <div class='field'>
      <label for='role'>Rolle</label>
      <select id='role' name='role' required>
        <option value='owner'>Owner/Admin</option>
        <option value='disposition'>Disposition</option>
        <option value='pruefer'>Prüfer</option>
        <option value='buchhaltung'>Buchhaltung</option>
        <option value='kunde'>Kunde</option>
      </select>
    </div>
    {label_input('Passwort', 'password', '', 'password')}
    <div class='field'>
      <label for='otp'>2FA-Code (optional)</label>
      <input id='otp' name='otp' placeholder='nur falls aktiviert' />
    </div>
    <div class='field'><button type='submit'>Anmelden</button></div>
  </form>
</div>
"""
        html = page("Login", body, "dashboard", show_logout=False, role="kunde")
        self.respond(html)

    def dashboard_page(self, cur: dict, platform) -> str:
        d = platform.dashboard()
        reminder_count = len(platform.escalation_reminders())
        sla = sla_monitor(platform, cur["tenant"])
        health = tenant_health_score(platform, cur["tenant"])
        lost = lost_revenue_list(platform)
        red_explain = explain_red_items(platform)
        updates = get_regulatory_updates()
        update_rows = "".join(
            f"<li><b>{escape(item['title'])}</b><br/><small class='muted'>{escape(item['published'])}</small></li>"
            for item in updates[:5]
        )
        due_rows = "".join(
            f"<tr><td>{escape(item['asset'])}</td><td>{escape(item['regulation'])}</td><td>{escape(item['due_date'])}</td><td>{traffic_badge(item['state'])}</td></tr>"
            for item in d["due_inspections"]
        ) or "<tr><td colspan='4'>Keine Prüfpläne vorhanden.</td></tr>"
        lost_rows = "".join(
            f"<tr><td>{escape(item['asset'])}</td><td>{escape(item['due_date'])}</td><td>{escape(item['reason'])}</td></tr>"
            for item in lost[:8]
        ) or "<tr><td colspan='3'>Kein verlorener Umsatz erkannt.</td></tr>"
        red_rows = "".join(
            f"<tr><td>{escape(item['asset'])}</td><td>{escape(item['reason'])}</td></tr>"
            for item in red_explain[:8]
        ) or "<tr><td colspan='2'>Keine roten Positionen.</td></tr>"

        invoice_states = {"offen": 0, "teilbezahlt": 0, "bezahlt": 0, "ueberfaellig": 0}
        for inv in platform.invoices.values():
            invoice_states[inv.status.value] = invoice_states.get(inv.status.value, 0) + 1

        due_states = {"rot": 0, "gelb": 0, "gruen": 0}
        for item in d["due_inspections"]:
            due_states[item["state"]] = due_states.get(item["state"], 0) + 1

        return f"""
<div class='card'>
  <h2>Willkommen, {cur['user_id']} ({ROLE_LABELS.get(cur['role'], cur['role'])})</h2>
  <p class='muted'>Live-Status der Prüfungen und Rechnungen. Aktualisiert alle 10 Sekunden.</p>
</div>
<div class='grid'>
  <div class='kpi'><small>Anlagen</small><h3 id='kpi-assets'>{d['assets']}</h3></div>
  <div class='kpi'><small>Prüfprotokolle</small><h3 id='kpi-records'>{d['inspection_records']}</h3></div>
  <div class='kpi'><small>Offene Rechnungen</small><h3 id='kpi-invoices'>{d['open_invoices']}</h3></div>
  <div class='kpi'><small>Eskalations-Reminder</small><h3 id='kpi-reminders'>{reminder_count}</h3></div>
  <div class='kpi'><small>SLA-Risiko</small><h3 id='kpi-sla'>{sla['sla_risk_score']}</h3></div>
  <div class='kpi'><small>Mandanten-Health</small><h3 id='kpi-health'>{health}</h3></div>
</div>
<div class='card stack'>
  <h3>Ampelsystem (Fälligkeiten)</h3>
  <div class='table-wrap'>
    <table>
      <tr><th>Anlage</th><th>Regelwerk</th><th>Fällig am</th><th>Status</th></tr>
      <tbody id='due-body'>{due_rows}</tbody>
    </table>
  </div>
  <small class='muted' id='live-updated'>Letztes Update: -</small>
</div>
<div class='grid'>
  <div class='card'>
    <h3>Diagramm: Fälligkeiten</h3>
    <canvas id='dueChart' width='420' height='220'></canvas>
  </div>
  <div class='card'>
    <h3>Diagramm: Rechnungsstatus</h3>
    <canvas id='invoiceChart' width='420' height='220'></canvas>
  </div>
</div>
<div class='card'>
  <h3>Aktuelle Bürokratie-/Regelwerks-Updates</h3>
  <ul id='reg-updates'>{update_rows}</ul>
  <p class='muted'>Automatisch aktualisiert (mit Fallback bei Verbindungsproblemen).</p>
</div>
<div class='grid'>
  <div class='card'><h3>Verlorener Umsatz</h3><div class='table-wrap'><table><tr><th>Asset</th><th>Fällig</th><th>Grund</th></tr>{lost_rows}</table></div></div>
  <div class='card'><h3>Warum ist das rot?</h3><div class='table-wrap'><table><tr><th>Asset</th><th>Erklärung</th></tr>{red_rows}</table></div></div>
</div>
<div class='card'>
  <h3>Schnellfunktionen</h3>
  <form method='post' action='/quick-seed'>
    {label_input('Vorlagen-Standort', 'location', 'Werk 1')}
    <div class='field'><button type='submit'>Demo-Anlage + Prüfplan automatisch anlegen</button></div>
  </form>
</div>
{info_box('Nächster Schritt', 'Gehe links auf „Anlagen & Prüfpläne“, dann auf „Prüfungen & Rechnungen“.')}
<script>
async function refreshDashboard() {{
  try {{
    const res = await fetch('/api/live-dashboard');
    if (!res.ok) return;
    const data = await res.json();
    const setKpi = (id, value) => {{
      const el = document.getElementById(id);
      if (!el) return;
      const prev = el.textContent;
      const next = String(value);
      if (prev !== next) {{
        el.textContent = next;
        const box = el.closest('.kpi');
        if (box) {{
          box.classList.add('changed');
          setTimeout(() => box.classList.remove('changed'), 350);
        }}
      }}
    }};
    setKpi('kpi-assets', data.assets);
    setKpi('kpi-records', data.inspection_records);
    setKpi('kpi-invoices', data.open_invoices);
    setKpi('kpi-reminders', data.reminders);
    setKpi('kpi-sla', data.sla_risk_score ?? '-');
    setKpi('kpi-health', data.tenant_health ?? '-');
    const body = document.getElementById('due-body');
    body.innerHTML = '';
    for (const item of data.due_inspections) {{
      const label = item.state === 'rot' ? 'Überfällig' : item.state === 'gelb' ? 'Bald fällig' : 'OK';
      const color = item.state === 'rot' ? '#d92d20' : item.state === 'gelb' ? '#f79009' : '#12b76a';
      const row = document.createElement('tr');
      row.className = 'row-enter';
      row.innerHTML = `<td>${{item.asset}}</td><td>${{item.regulation}}</td><td>${{item.due_date}}</td><td><span style="display:inline-flex;align-items:center;gap:.35rem"><span style="width:.62rem;height:.62rem;border-radius:999px;background:${{color}};display:inline-block"></span>${{label}}</span></td>`;
      body.appendChild(row);
    }}
    if (!data.due_inspections.length) {{
      body.innerHTML = '<tr><td colspan="4">Keine Prüfpläne vorhanden.</td></tr>';
    }}
    drawBarChart('dueChart', ['Rot','Gelb','Grün'], [data.due_states.rot || 0, data.due_states.gelb || 0, data.due_states.gruen || 0], ['#d92d20','#f79009','#12b76a']);
    drawBarChart('invoiceChart', ['Offen','Teil','Bezahlt','Überf.'], [data.invoice_states.offen || 0, data.invoice_states.teilbezahlt || 0, data.invoice_states.bezahlt || 0, data.invoice_states.ueberfaellig || 0], ['#f59e0b','#3b82f6','#22c55e','#ef4444']);
    document.getElementById('live-updated').textContent = `Letztes Update: ${{data.updated_at}}`;
  }} catch (e) {{
    // no-op for dashboard polling
  }}
}}
refreshDashboard();
setInterval(refreshDashboard, 10000);

function drawBarChart(canvasId, labels, values, colors) {{
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext('2d');
  const max = Math.max(...values, 1);
  ctx.clearRect(0,0,canvas.width,canvas.height);
  const padding = 28;
  const gap = 20;
  const barWidth = (canvas.width - padding * 2 - gap * (labels.length - 1)) / labels.length;
  values.forEach((v, i) => {{
    const h = ((canvas.height - 70) * v) / max;
    const x = padding + i * (barWidth + gap);
    const y = canvas.height - 40 - h;
    ctx.fillStyle = colors[i] || '#2563eb';
    ctx.fillRect(x, y, barWidth, h);
    ctx.fillStyle = '#334155';
    ctx.fillText(labels[i], x, canvas.height - 18);
    ctx.fillText(String(v), x + barWidth/3, y - 6);
  }});
}}

drawBarChart('dueChart', ['Rot','Gelb','Grün'], [{due_states['rot']}, {due_states['gelb']}, {due_states['gruen']}], ['#d92d20','#f79009','#12b76a']);
drawBarChart('invoiceChart', ['Offen','Teil','Bezahlt','Überf.'], [{invoice_states['offen']}, {invoice_states['teilbezahlt']}, {invoice_states['bezahlt']}, {invoice_states['ueberfaellig']}], ['#f59e0b','#3b82f6','#22c55e','#ef4444']);
</script>
"""

    def automation_page(self, cur: dict, platform, auto_page: str = "overview") -> str:
        tenant = cur["tenant"]
        route = load_json_file(SCHEDULE_DIR / f"{tenant}.json", {}).get("route", [])
        offer = load_json_file(OFFERS_DIR / f"{tenant}.json", {})
        tasks = load_json_file(TASKS_DIR / f"{tenant}.json", [])
        portal_items = load_json_file(PORTAL_DIR / f"{tenant}.json", [])
        report = load_json_file(REPORTS_DIR / f"{tenant}.json", {})
        subscriptions = load_json_file(SUBSCRIPTIONS_DIR / f"{tenant}.json", [])
        templates = load_compliance_templates(tenant)
        export_batches = sorted(EXPORTS_DIR.glob(f"{tenant}-*.json"), reverse=True)[:5]
        risk = build_risk_snapshot(platform)
        sla = sla_monitor(platform, tenant)
        health = tenant_health_score(platform, tenant)
        dunning = dunning_actions(platform)
        lost_revenue = lost_revenue_list(platform)
        red_explain = explain_red_items(platform)

        route_rows = "".join(
            f"<tr><td>{escape(item['inspector'])}</td><td>{escape(item['location'])}</td><td>{escape(item['asset'])}</td><td>{escape(item['due_date'])}</td></tr>"
            for item in route[:20]
        ) or "<tr><td colspan='4'>Noch keine Tourplanung erzeugt.</td></tr>"

        dunning_rows = "".join(
            f"<tr><td>{escape(item['invoice_id'])}</td><td>{escape(item['customer'])}</td><td>{escape(item['late_days'])}</td><td>{escape(item['level'])}</td></tr>"
            for item in dunning
        ) or "<tr><td colspan='4'>Keine Mahnfälle.</td></tr>"

        task_rows = "".join(
            f"<tr><td>{escape(t['task_id'])}</td><td>{escape(t['title'])}</td><td>{escape(t['owner'])}</td><td>{escape(t['due_date'])}</td><td>{escape(t['status'])}</td></tr>"
            for t in tasks[-15:]
        ) or "<tr><td colspan='5'>Keine Maßnahmen offen.</td></tr>"

        portal_rows = "".join(
            f"<tr><td>{escape(i['ticket_id'])}</td><td>{escape(i['asset'])}</td><td>{escape(i['status'])}</td><td>{escape(i['evidence'])}</td></tr>"
            for i in portal_items[-15:]
        ) or "<tr><td colspan='4'>Kein Portal-Feedback vorhanden.</td></tr>"

        lost_rows = "".join(
            f"<tr><td>{escape(i['plan_id'])}</td><td>{escape(i['asset'])}</td><td>{escape(i['due_date'])}</td><td>{escape(i['reason'])}</td></tr>"
            for i in lost_revenue[:20]
        ) or "<tr><td colspan='4'>Keine verlorenen Umsatz-Posten.</td></tr>"

        red_rows = "".join(
            f"<tr><td>{escape(i['asset'])}</td><td>{escape(i['reason'])}</td></tr>"
            for i in red_explain[:20]
        ) or "<tr><td colspan='2'>Keine roten Positionen.</td></tr>"

        sub_tabs = [
            ("overview", "Übersicht"),
            ("scheduling", "Terminierung"),
            ("billing", "Angebot & Abrechnung"),
            ("exceptions", "Ausnahmen"),
            ("reports", "Berichte & Export"),
        ]
        sub_nav = "".join(
            f"<a class='tab {'active' if key==auto_page else ''}' href='/?{urlencode({'page':'automation','auto':key})}'>{label}</a>"
            for key, label in sub_tabs
        )

        base = f"""
<div class='card'>
  <h2>Set-and-Forget Automationen</h2>
  <div class='grid'>
    <div class='kpi'><small>Risiko-Score</small><h3>{risk['risk_score']}</h3></div>
    <div class='kpi'><small>SLA-Risiko</small><h3>{sla['sla_risk_score']}</h3></div>
    <div class='kpi'><small>Mandanten-Health</small><h3>{health}</h3></div>
    <div class='kpi'><small>Überfällige Prüfungen</small><h3>{risk['overdue_due']}</h3></div>
    <div class='kpi'><small>Erstprüfung fehlt</small><h3>{len(risk['missing_initial'])}</h3></div>
    <div class='kpi'><small>Kosten von Nichtstun</small><h3>{cost_of_inaction(platform):.2f} €</h3></div>
  </div>
  <div class='tabs' style='margin-top:.8rem'>{sub_nav}</div>
</div>
"""

        if auto_page == "scheduling":
            return base + f"""
<div class='card'>
  <h3>Terminierung & Disposition</h3>
  <form method='post' action='/run-auto-schedule'>
    {label_input('Planungsdatum', 'planning_date', date.today().isoformat(), 'date', date.today().isoformat())}
    {label_input('Region / PLZ-Bereich', 'region_filter', 'z. B. 40***')}
    {label_input('Max. Stops pro Tour', 'max_stops', '8', 'number', '8')}
    <div class='field'><button type='submit'>Touren erzeugen</button></div>
  </form>
  <div class='table-wrap'><table><tr><th>Prüfer</th><th>Standort</th><th>Asset</th><th>Fällig</th></tr>{route_rows}</table></div>
</div>
"""

        if auto_page == "billing":
            return base + f"""
<div class='card'>
  <h3>Angebot, Vertrag & Abrechnung</h3>
  <form method='post' action='/generate-offer'>
    {label_input('Horizont in Tagen', 'horizon_days', '30', 'number', '30')}
    {label_input('Vertragsart', 'offer_contract_type', 'einzelauftrag / abo / rahmenvertrag')}
    {label_input('Express-Zuschlag %', 'offer_express_pct', '0', 'number', '0')}
    <div class='field'><button type='submit'>Auto-Angebot erzeugen</button></div>
  </form>
  <form method='post' action='/add-subscription'>
    {label_input('Abo-Kunde', 'sub_customer', 'Muster GmbH')}
    {label_input('Intervall in Tagen', 'sub_interval_days', '30', 'number', '30')}
    {label_input('Abo-Betrag', 'sub_amount', '399', 'number', '399')}
    {label_input('Vertragsart', 'sub_contract_type', 'abo')}
    <div class='field'><button type='submit'>Abo hinzufügen</button></div>
  </form>
  <form method='post' action='/run-recurring-invoices'>
    <div class='field'><label>Wiederholungsrechnung</label><button type='submit'>Abo-Rechnungen erzeugen</button></div>
  </form>
  <form method='post' action='/run-dunning'>
    <div class='field'><label>Mahnlogik / Eskalation</label><button type='submit'>Mahnläufe erzeugen</button></div>
  </form>
  <div class='table-wrap'><table><tr><th>Rechnung</th><th>Kunde</th><th>Tage</th><th>Level</th></tr>{dunning_rows}</table></div>
</div>
<div class='card'>
  <p class='muted'>Aktuelles Angebotspaket: {escape(str(offer.get('count', 0)))} Positionen / {escape(str(offer.get('offer_total_eur', 0)))} €</p>
  <p class='muted'>Abos aktiv: {len(subscriptions)}</p>
</div>
"""

        if auto_page == "exceptions":
            return base + f"""
<div class='card'>
  <h3>Ausnahmen & Folgeaktionen</h3>
  <form method='post' action='/report-exception'>
    {label_input('Ausnahmefall', 'exception_type', 'no_show / nicht_bestaetigt / anlage_nicht_verfuegbar / verschiebung')}
    {label_input('Plan-ID', 'exception_plan_id', 'p1')}
    {label_input('Ansprechpartner vor Ort', 'contact_person', 'Max Muster')}
    {label_input('Wunschtermin Neuplanung', 'desired_reschedule_date', date.today().isoformat(), 'date', date.today().isoformat())}
    {label_input('No-Show-Gebühr (optional)', 'no_show_fee', '0', 'number', '0')}
    {label_input('Notiz', 'exception_note', 'z. B. Kunde nicht angetroffen')}
    <div class='field'><button type='submit'>Ausnahme dokumentieren</button></div>
  </form>
  <form method='post' action='/run-no-show-cascade'>
    <div class='field'><label>No-Show-Kaskade</label><button type='submit'>Kaskade erzeugen</button></div>
  </form>
  <div class='grid'>
    <div class='card'><h4>Verlorener Umsatz (To-Do)</h4><div class='table-wrap'><table><tr><th>Plan</th><th>Asset</th><th>Fällig</th><th>Grund</th></tr>{lost_rows}</table></div></div>
    <div class='card'><h4>Warum ist rot?</h4><div class='table-wrap'><table><tr><th>Asset</th><th>Erklärung</th></tr>{red_rows}</table></div></div>
  </div>
</div>
"""

        if auto_page == "reports":
            return base + f"""
<div class='card'>
  <h3>Berichte, Portal & Export-Center</h3>
  <form method='post' action='/create-monthly-report'>
    <div class='field'><label>Kundenbericht</label><button type='submit'>Monatsbericht erstellen</button></div>
  </form>
  <form method='post' action='/send-management-report'>
    <div class='field'><label>Management-Mail (Montag 07:00)</label><button type='submit'>Wochenreport senden</button></div>
  </form>
  <form method='post' action='/portal-approve'>
    {label_input('Assetname', 'portal_asset', 'Schaltschrank A')}
    {label_input('Nachweisfoto', 'evidence', 'foto123.jpg')}
    <div class='field'><button type='submit'>Kundenportal-Freigabe erfassen</button></div>
  </form>
  <form method='post' action='/export-center'>
    {label_input('Export-Betreff', 'export_note', 'Monatsabschluss KW12')}
    <div class='field'><button type='submit'>PDF + DATEV + Monatsreport bündeln</button></div>
  </form>
  <div class='grid'>
    <div class='card'><h4>Maßnahmenplan</h4><div class='table-wrap'><table><tr><th>ID</th><th>Aufgabe</th><th>Owner</th><th>Fällig</th><th>Status</th></tr>{task_rows}</table></div></div>
    <div class='card'><h4>Kundenportal</h4><div class='table-wrap'><table><tr><th>Ticket</th><th>Asset</th><th>Status</th><th>Nachweis</th></tr>{portal_rows}</table></div></div>
  </div>
  <p class='muted'>Templates aktiv: {len(templates)} | Export-Batches: {len(export_batches)} | Letzter Monatsbericht: {escape(report.get('created_at', 'noch keiner'))}</p>
</div>
"""

        return base + f"""
<div class='card'>
  <h3>Übersicht</h3>
  <p class='muted'>Wähle oben einen Automations-Bereich. So bleiben Eingaben und Aktionen übersichtlich pro Arbeitsschritt.</p>
  <div class='grid'>
    <div class='card'><h4>Touren</h4><div class='table-wrap'><table><tr><th>Prüfer</th><th>Standort</th><th>Asset</th><th>Fällig</th></tr>{route_rows}</table></div></div>
    <div class='card'><h4>Mahnfälle</h4><div class='table-wrap'><table><tr><th>Rechnung</th><th>Kunde</th><th>Tage</th><th>Level</th></tr>{dunning_rows}</table></div></div>
  </div>
</div>
"""


    def users_page(self, cur: dict, platform) -> str:
        auth = load_auth().get(cur["tenant"], {"users": []})
        rows = "".join(
            f"<tr><td>{escape(u['user_id'])}</td><td>{escape(u['name'])}</td><td>{escape(u['role'])}</td><td>{escape(u.get('email',''))}</td></tr>"
            for u in auth["users"]
        ) or "<tr><td colspan='4'>Keine Benutzer vorhanden.</td></tr>"
        admin_note = "nur Admin" if not self.require_admin() else ""
        return f"""
<div class='card'>
  <h2>Benutzerverwaltung {admin_note}</h2>
  {info_box('Was und warum?', 'Hier verwaltest du Zugänge pro Kunde/Tenant. Nur Admin darf Benutzer ändern.')}
  <form method='post' action='/user-create'>
    {label_input('Neue Benutzer-ID', 'user_id', 'z. B. pruefer1')}
    {label_input('Name', 'name', 'Max Mustermann')}
    <div class='field'><label for='role'>Rolle</label><select id='role' name='role' required><option value='admin'>Admin</option><option value='pruefer'>Prüfer</option><option value='kunde'>Kunde</option></select></div>
    <div class='field'><label for='email'>E-Mail</label><input id='email' name='email' placeholder='name@firma.de'/></div>
    {label_input('Passwort', 'password', '', 'password')}
    <div class='field'><label for='otp_secret'>2FA Secret (optional)</label><input id='otp_secret' name='otp_secret' placeholder='optional'/></div>
    <div class='field'><button type='submit'>Benutzer anlegen</button></div>
  </form>
</div>
<div class='card'>
  <form method='post' action='/user-reset-password'>
    {label_input('Benutzer-ID', 'user_id', 'z. B. pruefer1')}
    {label_input('Neues Passwort', 'new_password', '', 'password')}
    <div class='field'><button type='submit'>Passwort zurücksetzen</button></div>
  </form>
  <form method='post' action='/user-delete'>
    {label_input('Benutzer-ID löschen', 'user_id', 'z. B. kunde1')}
    <div class='field'><button type='submit'>Benutzer löschen</button></div>
  </form>
</div>
<div class='card table-wrap'><table><tr><th>User-ID</th><th>Name</th><th>Rolle</th><th>E-Mail</th></tr>{rows}</table></div>
"""

    def assets_page(self, platform) -> str:
        return f"""
<div class='card'>
  <h2>Anlagen & Prüfpläne</h2>
  {info_box('Was und warum?', 'Lege erst Anlagen, dann Prüfpläne an. Ohne Prüfplan keine fälligen Prüfungen.')}
  <form method='post' action='/add-asset-plan'>
    {label_input('Asset-ID', 'asset_id', 'a1')}
    {label_input('Anlagenname', 'asset_name', 'Schaltschrank A')}
    {label_input('Seriennummer', 'serial', 'SN-001')}
    {label_input('Standort', 'location', 'Werk 1')}
    {label_input('Anlagentyp', 'asset_type', 'Elektroanlage')}
    {label_input('Plan-ID', 'plan_id', 'p1')}
    {label_input('Regelwerk', 'regulation', 'DGUV V3')}
    {label_input('Intervall (Tage)', 'interval_days', '180', 'number', '180')}
    <div class='field'><button type='submit'>Anlage + Plan speichern</button></div>
  </form>
</div>
"""

    def records_page(self, cur: dict, platform) -> str:
        rows = "".join(
            f"<tr><td>{escape(r.record_id)}</td><td>{escape(r.plan_id)}</td><td>{escape(r.result)}</td><td>{r.updated_at.isoformat()}</td><td><a href='/export-record-pdf?record_id={escape(r.record_id)}'>PDF</a></td></tr>"
            for r in platform.records.values()
        ) or "<tr><td colspan='5'>Keine Prüfprotokolle vorhanden.</td></tr>"
        return f"""
<div class='card'>
  <h2>Prüfungen & Rechnungen</h2>
  {info_box('Was und warum?', 'Hier entsteht der Kernprozess: Prüfung dokumentieren und (als Admin) Rechnung erstellen.')}
  <form method='post' action='/record-and-invoice'>
    {label_input('Protokoll-ID', 'record_id', 'r1')}
    {label_input('Plan-ID', 'plan_id', 'p1')}
    {label_input('Prüfer-ID', 'inspector_id', 'pruefer1')}
    {label_input('Ergebnis', 'result', 'bestanden', 'text', 'bestanden')}
    {label_input('Messwert', 'measurement', 'z. B. 0.22 Ohm')}
    {label_input('Anhang/Foto', 'attachment_ref', 'z. B. foto-001.jpg')}
    {label_input('Signatur (Name)', 'signature_name', 'z. B. M. Prüfer')}
    {label_input('Kunden-Signatur (optional)', 'customer_signature', 'z. B. Kunde A')}
    {label_input('Template-Zusatzfeld (optional)', 'required_extra_value', 'z. B. Serienfoto-ID')}
    <div class='field'><label for='findings'>Feststellungen</label><textarea id='findings' name='findings' placeholder='z. B. Keine Mängel' required>Keine Mängel</textarea></div>
    {label_input('Rechnungs-ID', 'invoice_id', 'i1')}
    {label_input('Kunde', 'invoice_customer', 'Muster GmbH')}
    {label_input('Preis pro Prüfung', 'price', '149', 'number', '149')}
    <div class='field'><button type='submit'>Prüfung speichern / Rechnung anlegen</button></div>
  </form>
  <p class='muted'>Hinweis: Rechnung wird nur erstellt, wenn du als Admin angemeldet bist (aktuell: {cur['role']}).</p>
</div>
<div class='card table-wrap'><table><tr><th>ID</th><th>Plan</th><th>Ergebnis</th><th>Aktualisiert</th><th>Export</th></tr>{rows}</table></div>
"""

    def imports_page(self, cur: dict) -> str:
        return f"""
<div class='card'>
  <h2>Import / Export / Hilfsoptionen</h2>
  {info_box('Was und warum?', 'Mit CSV kannst du schnell viele Daten laden; mit DATEV und PDF exportierst du Ergebnisse.')}
  <form method='post' action='/import-csv'>
    <div class='field'><label for='kind'>CSV-Typ</label><select id='kind' name='kind' required><option value='assets'>Assets</option><option value='plans'>Prüfpläne</option></select></div>
    <div class='field' style='grid-column:1/-1'><label for='csv_text'>CSV-Inhalt</label><textarea id='csv_text' name='csv_text' placeholder='Header + Zeilen einfügen' required></textarea></div>
    <div class='field'><button type='submit'>CSV importieren (Admin)</button></div>
  </form>
  <div class='grid'>
    <div class='card'>
      <h4>Beispiel Assets</h4>
      <pre>asset_id,name,serial_number,location,asset_type\na1,Schaltschrank A,SN-001,Werk 1,Elektroanlage</pre>
    </div>
    <div class='card'>
      <h4>Beispiel Prüfpläne</h4>
      <pre>plan_id,asset_id,regulation,interval_days\np1,a1,DGUV V3,180</pre>
    </div>
  </div>
  <p><a href='/export-datev'>DATEV-CSV exportieren</a></p>
</div>
<div class='card'>
  <form method='post' action='/pay-invoice'>
    {label_input('Rechnungs-ID', 'invoice_id', 'i1')}
    {label_input('Zahlungsbetrag', 'amount', '100', 'number')}
    <div class='field'><button type='submit'>Zahlung buchen (Admin)</button></div>
  </form>
  <form method='post' action='/run-reminders'>
    <div class='field'><label>Reminder auslösen</label><button type='submit'>Eskalationsmails senden</button></div>
  </form>
</div>
<div class='card'>
  <h4>API-Hilfe</h4>
  <p class='muted'>JWT Login: <code>POST /api/v1/login</code>, Dashboard: <code>GET /api/v1/dashboard</code>, Sync: <code>POST /api/v1/sync</code></p>
  <p class='muted'>Aktuelle Rolle: {cur['role']}</p>
</div>
"""

    def help_page(self) -> str:
        return """
<div class='card'>
  <h2>Hilfe & Ablauf</h2>
  <ol>
    <li>Benutzer anlegen (Admin)</li>
    <li>Anlage + Prüfplan anlegen</li>
    <li>Prüfung erfassen</li>
    <li>Rechnung erstellen / Zahlung buchen</li>
    <li>PDF/DATEV exportieren</li>
    <li>AI-Assistent nutzen, um nächste Schritte/Fälligkeiten abzufragen</li>
  </ol>
  <p class='muted'>Tipp: Siehe auch BEDIENUNGSANLEITUNG.md im Projektordner.</p>
</div>
"""

    def ai_page(self, cur: dict, platform) -> str:
        history = cur.get("ai_history", [])
        bubbles = []
        for item in history[-12:]:
            bubbles.append(f"<div class='bubble user'>{escape(item['q'])}</div>")
            bubbles.append(
                f"<div class='bubble ai' data-full='{escape(item['a'])}'>{escape(item['a'])}</div>"
            )
        history_html = "".join(bubbles) or "<p class='muted'>Noch keine Fragen gestellt.</p>"
        pending = cur.get("pending_ai_action", "")
        pending_box = ""
        if pending:
            pending_box = (
                "<div class='card'><b>Ausstehende AI-Aktion:</b> "
                + escape(pending)
                + "<form method='post' action='/confirm-ai-action'><button type='submit'>Aktion bestätigen</button></form></div>"
            )

        return f"""
<div class='card'>
  <h2 class='page-title'>AI-Chat</h2>
  {info_box('Sicherer Modus', 'Die AI kann Aktionen nur vorschlagen. Ausführung erfolgt erst nach deiner expliziten Bestätigung.')}
  <div class='quick-actions'>
  <button type="button" class="quick-btn" data-quick="abrechnungsvorschlag:Muster GmbH|149">Angebot generieren</button>
  <button type="button" class="quick-btn" data-quick="Welche Termine sind kritisch und was schlägst du vor?">Termin vorschlagen</button>
  <button type="button" class="quick-btn" data-quick="qualitaetscheck:p1|0.21 Ohm|foto-001.jpg|M. Prüfer">Protokoll prüfen</button>
  </div>
  <form method='post' action='/ask-ai'>
    <div class='field' style='grid-column:1/-1'>
      <label for='question'>Nachricht</label>
      <textarea id='question' name='question' placeholder='Frage oder Befehlsvorschlag eingeben…' required></textarea>
    </div>
    <div class='field'><button type='submit'>Senden</button></div>
  </form>
</div>
{pending_box}
<div class='card'>
  <h3>Chatverlauf</h3>
  <div class='chat' id='chat'>{history_html}</div>
</div>
<script>
function md(text) {{
  let out = text.replace(/\*\*(.*?)\*\*/g, '<b>$1</b>').replace(/`(.*?)`/g, '<code>$1</code>').replace(/\n/g, '<br/>');
  return out;
}}
for (const node of document.querySelectorAll('.bubble.ai[data-full]')) {{
  const full = node.getAttribute('data-full') || '';
  node.textContent = '';
  let i = 0;
  const timer = setInterval(() => {{
    i += 2;
    node.innerHTML = md(full.slice(0, i));
    if (i >= full.length) clearInterval(timer);
  }}, 14);
}}
(function () {{
  const textarea = document.getElementById('question');

  document.querySelectorAll('.quick-btn').forEach(btn => {{
    btn.addEventListener('click', () => {{
      const text = btn.getAttribute('data-quick') || '';
      if (textarea) {{
        textarea.value = text;
        textarea.focus();
      }}
    }});
  }});
}})();
</script>
"""


    # ---------- POST ----------
    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/v1/login":
            payload = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
                or "{}"
            )
            tenant = payload.get("tenant", "").strip().lower()
            user_id = payload.get("user_id", "")
            role = payload.get("role", "")
            password = payload.get("password", "")
            otp = payload.get("otp", "")
            users = {
                u["user_id"]: u
                for u in load_auth().get(tenant, {}).get("users", [])
            }
            user = users.get(user_id)
            if not user or user["role"] != role or user["password_hash"] != hash_password(password):
                self.send_error(401)
                return
            if user.get("otp_secret") and otp != user["otp_secret"][-6:]:
                self.send_error(401)
                return
            token = sign_jwt(
                {
                    "tenant": tenant,
                    "user_id": user_id,
                    "role": role,
                    "exp": int(datetime.utcnow().timestamp()) + 3600,
                }
            )
            self.json_response({"token": token})
            return

        if parsed.path == "/api/v1/sync":
            auth = self.headers.get("Authorization", "")
            jwt_payload = verify_jwt(auth.replace("Bearer ", "")) if auth.startswith("Bearer ") else None
            if not jwt_payload:
                self.send_error(401)
                return
            items = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
                or "[]"
            )
            platform = storage.load(jwt_payload["tenant"])
            stats = {"created": 0, "updated": 0, "ignored": 0}
            for item in items:
                result = platform.merge_record(
                    InspectionRecord(
                        record_id=item["record_id"],
                        plan_id=item["plan_id"],
                        inspector_id=item["inspector_id"],
                        performed_on=date.fromisoformat(
                            item.get("performed_on", date.today().isoformat())
                        ),
                        result=item.get("result", "bestanden"),
                        findings=item.get("findings", ""),
                        updated_at=datetime.fromisoformat(
                            item.get("updated_at", datetime.utcnow().isoformat())
                        ),
                    )
                )
                stats[result] += 1
            storage.save(jwt_payload["tenant"], platform)
            self.json_response(stats)
            return

        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))

        if parsed.path == "/login":
            self.handle_login(form)
            return
        if parsed.path == "/logout":
            self.handle_logout()
            return

        cur = self.current()
        if not cur:
            self.redirect("/")
            return

        platform = storage.load(cur["tenant"])
        auth_data = load_auth()
        auth_data.setdefault(cur["tenant"], {"users": []})

        try:
            if parsed.path == "/user-create":
                if not self.require_capability("manage_users"):
                    self.send_error(403)
                    return
                users = {u["user_id"]: u for u in auth_data[cur["tenant"]]["users"]}
                users[form["user_id"][0]] = {
                    "user_id": form["user_id"][0],
                    "name": form["name"][0],
                    "role": form["role"][0],
                    "email": form.get("email", [""])[0],
                    "password_hash": hash_password(form["password"][0]),
                    "otp_secret": form.get("otp_secret", [""])[0],
                }
                auth_data[cur["tenant"]]["users"] = list(users.values())
                save_auth(auth_data)
                platform.add_user(
                    User(
                        form["user_id"][0],
                        form["name"][0],
                        to_domain_role(form["role"][0]),
                        form.get("email", [""])[0],
                    )
                )
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "user_create", {"user_id": form["user_id"][0]})

            elif parsed.path == "/user-delete":
                if not self.require_capability("manage_users"):
                    self.send_error(403)
                    return
                user_id = form["user_id"][0]
                auth_data[cur["tenant"]]["users"] = [
                    u for u in auth_data[cur["tenant"]]["users"] if u["user_id"] != user_id
                ]
                save_auth(auth_data)
                platform.users.pop(user_id, None)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "user_delete", {"user_id": user_id})

            elif parsed.path == "/user-reset-password":
                if not self.require_capability("manage_users"):
                    self.send_error(403)
                    return
                uid = form["user_id"][0]
                for u in auth_data[cur["tenant"]]["users"]:
                    if u["user_id"] == uid:
                        u["password_hash"] = hash_password(form["new_password"][0])
                save_auth(auth_data)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "user_reset_password", {"user_id": uid})

            elif parsed.path == "/add-asset-plan":
                if not self.require_capability("plan"):
                    self.send_error(403)
                    return
                platform.add_asset(
                    Asset(
                        form["asset_id"][0],
                        form["asset_name"][0],
                        form["serial"][0],
                        form["location"][0],
                        form["asset_type"][0],
                    )
                )
                platform.add_plan(
                    InspectionPlan(
                        form["plan_id"][0],
                        form["asset_id"][0],
                        form["regulation"][0],
                        int(form["interval_days"][0]),
                    )
                )
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "add_asset_plan", {"asset_id": form["asset_id"][0]})

            elif parsed.path == "/record-and-invoice":
                if not self.require_capability("inspect"):
                    self.send_error(403)
                    return
                record_id = form["record_id"][0]
                plan_id = form["plan_id"][0]
                plan = platform.plans.get(plan_id)
                if not plan:
                    raise ValueError("Prüfplan nicht gefunden")
                measurement = self.safe_form_value(form, "measurement")
                attachment_ref = self.safe_form_value(form, "attachment_ref")
                signature_name = self.safe_form_value(form, "signature_name")
                customer_signature = self.safe_form_value(form, "customer_signature")
                required_extra_value = self.safe_form_value(form, "required_extra_value")
                findings = form["findings"][0]
                invoice_customer = self.safe_form_value(form, "invoice_customer")
                is_valid, required_label = validate_template_requirements(cur["tenant"], invoice_customer, required_extra_value)
                if not is_valid:
                    raise ValueError(required_label)
                if "DGUV" in plan.regulation and len(measurement) < 2:
                    raise ValueError("DGUV-Protokoll benötigt einen Messwert")
                if "TRBS" in plan.regulation and len(attachment_ref) < 3:
                    raise ValueError("TRBS-Protokoll benötigt einen Anhang/Foto")
                if len(signature_name) < 2:
                    raise ValueError("Digitale Signatur fehlt")
                before = platform.records[record_id].findings if record_id in platform.records else ""
                customer_step = customer_signature if customer_signature else "offen"
                template_part = f" | Template-Feld: {required_extra_value}" if required_extra_value else ""
                platform.record_inspection(
                    InspectionRecord(
                        record_id,
                        plan_id,
                        form["inspector_id"][0],
                        date.today(),
                        form["result"][0],
                        f"{findings} | Messwert: {measurement} | Anhang: {attachment_ref} | Prüfer-Signatur: {signature_name} | Kunden-Bestätigung: {customer_step}{template_part}",
                    )
                )
                if before:
                    record_diff(cur["tenant"], record_id, before, platform.records[record_id].findings)
                if self.require_capability("billing"):
                    platform.create_invoice(
                        form["invoice_id"][0],
                        invoice_customer,
                        [record_id],
                        float(form["price"][0]),
                    )
                if not customer_signature:
                    portal_items = load_json_file(PORTAL_DIR / f"{cur['tenant']}.json", [])
                    portal_items.append({"ticket_id": f"P{len(portal_items)+1}", "asset": platform.assets[plan.asset_id].name, "status": "Warten auf Kunden-Signatur", "evidence": "-", "created_at": datetime.utcnow().isoformat(timespec="seconds")})
                    save_json_file(PORTAL_DIR / f"{cur['tenant']}.json", portal_items)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "record_and_invoice", {"record_id": record_id, "customer_signed": bool(customer_signature)})

            elif parsed.path == "/import-csv":
                if not self.require_capability("import_export"):
                    self.send_error(403)
                    return
                rows = parse_csv_rows(form["csv_text"][0])
                kind = form["kind"][0]
                if kind == "assets":
                    for row in rows:
                        platform.add_asset(
                            Asset(
                                row["asset_id"],
                                row["name"],
                                row["serial_number"],
                                row["location"],
                                row["asset_type"],
                            )
                        )
                else:
                    for row in rows:
                        platform.add_plan(
                            InspectionPlan(
                                row["plan_id"],
                                row["asset_id"],
                                row["regulation"],
                                int(row["interval_days"]),
                            )
                        )
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "import_csv", {"rows": len(rows), "kind": kind})

            elif parsed.path == "/pay-invoice":
                if not self.require_capability("billing"):
                    self.send_error(403)
                    return
                inv = platform.update_invoice_payment(
                    form["invoice_id"][0], float(form["amount"][0])
                )
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "pay_invoice", {"invoice_id": inv.invoice_id, "status": inv.status.value})

            elif parsed.path == "/run-reminders":
                if not self.require_capability("automation"):
                    self.send_error(403)
                    return
                sent = send_escalation_emails(cur["tenant"], platform)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "run_reminders", {"sent": sent})

            elif parsed.path == "/quick-seed":
                if not self.require_capability("plan"):
                    self.send_error(403)
                    return
                location = self.safe_form_value(form, "location")
                asset_id = self.next_id("a", platform.assets)
                plan_id = self.next_id("p", platform.plans)
                platform.add_asset(
                    Asset(asset_id, "Demo-Anlage", f"SN-{asset_id}", location, "Elektroanlage")
                )
                platform.add_plan(InspectionPlan(plan_id, asset_id, "DGUV V3", 180))
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "quick_seed", {"asset_id": asset_id, "plan_id": plan_id})

            elif parsed.path == "/run-auto-schedule":
                planning_date = self.optional_form_value(form, "planning_date", date.today().isoformat())
                region_filter = self.optional_form_value(form, "region_filter", "")
                max_stops = int(self.optional_form_value(form, "max_stops", "8") or "8")
                route = generate_route_plan(platform)
                save_json_file(SCHEDULE_DIR / f"{cur['tenant']}.json", {"created_at": datetime.utcnow().isoformat(timespec="seconds"), "planning_date": planning_date, "region_filter": region_filter, "max_stops": max_stops, "route": route[:max(1,max_stops*5)]})
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "auto_schedule", {"count": len(route)})
                self.redirect_with_message(f"Tourplanung erstellt ({len(route)} Einträge).", page_name="automation")
                return

            elif parsed.path == "/generate-offer":
                horizon = int(self.safe_form_value(form, "horizon_days"))
                contract_type = self.optional_form_value(form, "offer_contract_type", "einzelauftrag")
                express_pct = float(self.optional_form_value(form, "offer_express_pct", "0") or "0")
                offer = create_due_offer(platform, horizon)
                offer["contract_type"] = contract_type
                offer["express_pct"] = express_pct
                offer["offer_total_eur"] = round(float(offer["offer_total_eur"]) * (1 + express_pct / 100), 2)
                save_json_file(OFFERS_DIR / f"{cur['tenant']}.json", offer)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "auto_offer", {"count": offer["count"], "total": offer["offer_total_eur"]})
                self.redirect_with_message("Auto-Angebot erzeugt.", page_name="automation")
                return

            elif parsed.path == "/run-dunning":
                actions = dunning_actions(platform)
                save_json_file(Path("data") / "dunning" / f"{cur['tenant']}.json", {"created_at": datetime.utcnow().isoformat(timespec="seconds"), "actions": actions})
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "run_dunning", {"count": len(actions)})
                self.redirect_with_message(f"Mahnlogik ausgeführt ({len(actions)} Fälle).", page_name="automation")
                return

            elif parsed.path == "/run-no-show-cascade":
                pending = [d for d in platform.dashboard()["due_inspections"] if d["state"] in {"rot", "gelb"}]
                calls = []
                for idx, item in enumerate(pending[:20]):
                    calls.append(
                        {
                            "call_id": f"C{idx+1}",
                            "asset": item["asset"],
                            "step": "Kunde > Teamleiter > Eskalation > Call-Task",
                            "status": "offen",
                        }
                    )
                save_json_file(Path("data") / "noshow" / f"{cur['tenant']}.json", {"created_at": datetime.utcnow().isoformat(timespec="seconds"), "calls": calls})
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "run_no_show", {"count": len(calls)})
                self.redirect_with_message(f"No-Show-Kaskade erstellt ({len(calls)} Tasks).", page_name="automation")
                return

            elif parsed.path == "/create-monthly-report":
                report = monthly_customer_report(platform)
                save_json_file(REPORTS_DIR / f"{cur['tenant']}.json", report)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "monthly_report", {"records": report["records"]})
                self.redirect_with_message("Monatsbericht erstellt.", page_name="automation")
                return

            elif parsed.path == "/send-management-report":
                d = platform.dashboard()
                risk = build_risk_snapshot(platform)
                summary = (
                    f"Wochenreport: offen={d['open_invoices']}, Umsatz offen={d['open_revenue_eur']:.2f} €, "
                    f"Risiko-Score={risk['risk_score']}, überfällige Prüfungen={risk['overdue_due']}"
                )
                maybe_send_email(f"management@{cur['tenant']}.local", "Wochenreport Montag 07:00", summary)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "management_report", {"summary": summary})
                self.redirect_with_message("Management-Report versendet.", page_name="automation")
                return

            elif parsed.path == "/portal-approve":
                asset = self.safe_form_value(form, "portal_asset")
                evidence = self.safe_form_value(form, "evidence")
                items = load_json_file(PORTAL_DIR / f"{cur['tenant']}.json", [])
                items.append({"ticket_id": f"P{len(items)+1}", "asset": asset, "status": "behoben gemeldet", "evidence": evidence, "created_at": datetime.utcnow().isoformat(timespec="seconds")})
                save_json_file(PORTAL_DIR / f"{cur['tenant']}.json", items)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "portal_approve", {"asset": asset})
                self.redirect_with_message("Kundenportal-Freigabe gespeichert.", page_name="automation")
                return


            elif parsed.path == "/report-exception":
                ex_type = self.safe_form_value(form, "exception_type").lower()
                plan_id = self.safe_form_value(form, "exception_plan_id")
                note = self.safe_form_value(form, "exception_note")
                fee = float(self.optional_form_value(form, "no_show_fee", "0") or "0")
                contact_person = self.optional_form_value(form, "contact_person", "")
                desired_reschedule_date = self.optional_form_value(form, "desired_reschedule_date", "")
                exceptions_file = Path("data") / "exceptions" / f"{cur['tenant']}.json"
                items = load_json_file(exceptions_file, [])
                entry = {
                    "id": f"E{len(items)+1}",
                    "type": ex_type,
                    "plan_id": plan_id,
                    "note": note,
                    "contact_person": contact_person,
                    "desired_reschedule_date": desired_reschedule_date,
                    "created_at": datetime.utcnow().isoformat(timespec="seconds"),
                    "follow_up": "Neuplanung + Reminder",
                }
                items.append(entry)
                save_json_file(exceptions_file, items)
                maybe_send_email(f"dispo@{cur['tenant']}.local", f"Ausnahmefall {ex_type}", f"Plan {plan_id}: {note}")
                if ex_type == "no_show" and fee > 0 and self.require_capability("billing"):
                    invoice_id = f"inoshow-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                    inv = platform.create_invoice(invoice_id, "No-Show", [], fee)
                    inv.amount_eur = fee
                    inv.source_record_ids = []
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "report_exception", {"type": ex_type, "plan_id": plan_id, "fee": fee})
                self.redirect_with_message("Ausnahme dokumentiert und Folgeaktion ausgelöst.", page_name="automation")
                return

            elif parsed.path == "/set-sla-contract":
                if not self.require_capability("automation"):
                    self.send_error(403)
                    return
                sla_days = int(self.safe_form_value(form, "sla_days"))
                save_json_file(CONTRACTS_DIR / f"{cur['tenant']}.json", {"sla_days": max(1, sla_days)})
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "set_sla_contract", {"sla_days": sla_days})
                self.redirect_with_message("SLA-Vertrag gespeichert.", page_name="automation")
                return

            elif parsed.path == "/add-subscription":
                if not self.require_capability("billing"):
                    self.send_error(403)
                    return
                subs = load_json_file(SUBSCRIPTIONS_DIR / f"{cur['tenant']}.json", [])
                customer = self.safe_form_value(form, "sub_customer")
                interval_days = int(self.safe_form_value(form, "sub_interval_days"))
                amount = float(self.safe_form_value(form, "sub_amount"))
                subs.append({
                    "customer": customer,
                    "interval_days": max(1, interval_days),
                    "amount": amount,
                    "contract_type": self.optional_form_value(form, "sub_contract_type", "abo"),
                    "next_run": date.today().isoformat(),
                })
                save_json_file(SUBSCRIPTIONS_DIR / f"{cur['tenant']}.json", subs)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "add_subscription", {"customer": customer, "interval_days": interval_days})
                self.redirect_with_message("Abo gespeichert.", page_name="automation")
                return

            elif parsed.path == "/run-recurring-invoices":
                if not self.require_capability("billing"):
                    self.send_error(403)
                    return
                created = recurring_invoice_run(platform, cur["tenant"])
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "run_recurring_invoices", {"created": len(created)})
                self.redirect_with_message(f"Wiederholungsrechnungen erstellt: {len(created)}", page_name="automation")
                return

            elif parsed.path == "/save-compliance-template":
                if not self.require_capability("automation"):
                    self.send_error(403)
                    return
                key = self.safe_form_value(form, "template_customer").lower()
                required_extra = self.safe_form_value(form, "required_extra")
                templates = load_compliance_templates(cur["tenant"])
                templates[key] = {"required_extra": required_extra}
                save_json_file(TEMPLATES_DIR / f"{cur['tenant']}.json", templates)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "save_compliance_template", {"template_customer": key})
                self.redirect_with_message("Compliance-Template gespeichert.", page_name="automation")
                return

            elif parsed.path == "/bulk-update":
                if not self.require_capability("automation"):
                    self.send_error(403)
                    return
                from_loc = self.safe_form_value(form, "from_location")
                to_loc = self.safe_form_value(form, "to_location")
                new_interval_raw = self.safe_form_value(form, "new_interval_days")
                new_interval = int(new_interval_raw) if new_interval_raw else None
                changed_assets = 0
                changed_plans = 0
                for asset in platform.assets.values():
                    if asset.location == from_loc:
                        asset.location = to_loc
                        changed_assets += 1
                if new_interval:
                    for plan in platform.plans.values():
                        asset = platform.assets.get(plan.asset_id)
                        if asset and asset.location == to_loc:
                            plan.interval_days = new_interval
                            changed_plans += 1
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "bulk_update", {"assets": changed_assets, "plans": changed_plans})
                self.redirect_with_message(f"Bulk-Update fertig: Assets={changed_assets}, Pläne={changed_plans}", page_name="automation")
                return

            elif parsed.path == "/export-center":
                if not self.require_capability("import_export"):
                    self.send_error(403)
                    return
                d = platform.dashboard()
                batch_id = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                report = monthly_customer_report(platform)
                datev_rows = platform.datev_export_rows()
                export_note = self.optional_form_value(form, "export_note", "")
                export_payload = {
                    "batch_id": batch_id,
                    "created_at": datetime.utcnow().isoformat(timespec="seconds"),
                    "tenant": cur["tenant"],
                    "monthly_report": report,
                    "datev_rows": datev_rows,
                    "pdf_records": list(platform.records.keys()),
                    "kpi": {
                        "open_invoices": d["open_invoices"],
                        "open_revenue_eur": d["open_revenue_eur"],
                    },
                    "note": export_note,
                }
                save_json_file(EXPORTS_DIR / f"{cur['tenant']}-{batch_id}.json", export_payload)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "export_center", {"batch_id": batch_id})
                self.redirect_with_message(f"Export-Batch {batch_id} erstellt.", page_name="automation")
                return
            
            elif parsed.path == "/ask-ai":
                question = self.safe_form_value(form, "question").strip()

                prefix = question.split(":", 1)[0].lower()
                command_like = (":" in question) and (prefix in AI_ACTION_PREFIXES)

                if command_like:
                    cur["pending_ai_action"] = question
                    answer = "Vorschlag erkannt. Bitte Aktion explizit bestätigen, bevor Daten geändert werden."
                else:
                    answer = build_ai_answer(question, platform)

                cur.setdefault("ai_history", []).append({"q": question, "a": answer})
                cur["ai_history"] = cur["ai_history"][-12:]
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "ask_ai", {"question": question[:80], "pending": command_like})
                storage.save(cur["tenant"], platform)
                self.redirect_with_message("AI-Nachricht verarbeitet.", page_name="ai")
                return

            elif parsed.path == "/confirm-ai-action":
                if not self.require_capability("ai_execute"):
                    self.send_error(403)
                    return
                pending = cur.get("pending_ai_action", "")
                if not pending:
                    self.redirect_with_message("Keine AI-Aktion zur Bestätigung vorhanden.", kind="error", page_name="ai")
                    return
                answer, changed = execute_ai_action(pending, platform, auth_data, cur["tenant"], self.next_id)
                cur.setdefault("ai_history", []).append({"q": f"Bestätigt: {pending}", "a": answer})
                cur["ai_history"] = cur["ai_history"][-12:]
                cur.pop("pending_ai_action", None)
                write_audit(cur["tenant"], cur["user_id"], cur["role"], "confirm_ai_action", {"action": pending[:80]})
                if changed:
                    save_auth(auth_data)
                storage.save(cur["tenant"], platform)
                self.redirect_with_message("AI-Aktion ausgeführt.", page_name="ai")
                return

            else:
                self.send_error(404)
                return

        except (ValueError, KeyError) as err:
            self.redirect_with_message(f"Eingabefehler: {err}", kind="error")
            return

        storage.save(cur["tenant"], platform)
        self.redirect_with_message("Änderung gespeichert.", kind="ok")

    def handle_login(self, form: dict) -> None:
        tenant = form.get("tenant", [""])[0].strip().lower()
        user_id = form.get("user_id", [""])[0]
        role = form.get("role", [""])[0]
        password = form.get("password", [""])[0]
        otp = form.get("otp", [""])[0]

        auth = load_auth()
        auth.setdefault(tenant, {"users": []})
        users = {u["user_id"]: u for u in auth[tenant]["users"]}

        if user_id not in users:
            if role not in {"owner", "admin"} and auth[tenant]["users"]:
                self.redirect_with_message("Login nicht möglich: Benutzer existiert nicht.", kind="error")
                return
            users[user_id] = {
                "user_id": user_id,
                "name": user_id,
                "role": role,
                "email": "",
                "password_hash": hash_password(password),
                "otp_secret": "",
            }
            auth[tenant]["users"] = list(users.values())
            save_auth(auth)

        user = users.get(user_id)
        if not user or user["role"] != role or user["password_hash"] != hash_password(password):
            self.redirect_with_message("Login fehlgeschlagen. Bitte Daten prüfen.", kind="error")
            return
        if user.get("otp_secret") and otp != user["otp_secret"][-6:]:
            self.redirect_with_message("2FA-Code ungültig.", kind="error")
            return

        token = secrets.token_hex(16)
        SESSIONS[token] = {"tenant": tenant, "user_id": user_id, "role": role}
        self.send_response(303)
        self.send_header("Set-Cookie", f"session={token}; HttpOnly; Path=/")
        self.send_header("Location", "/")
        self.end_headers()

    def handle_logout(self) -> None:
        c = cookies.SimpleCookie(self.headers.get("Cookie"))
        t = c.get("session")
        if t and t.value in SESSIONS:
            del SESSIONS[t.value]
        self.send_response(303)
        self.send_header("Set-Cookie", "session=; Max-Age=0; Path=/")
        self.send_header("Location", "/")
        self.end_headers()

    def respond(self, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def json_response(self, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, target: str) -> None:
        self.send_response(303)
        self.send_header("Location", target)
        self.end_headers()


def run() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    print("Web-Dashboard läuft auf http://localhost:8000")
    server.serve_forever()


if __name__ == "__main__":
    run()