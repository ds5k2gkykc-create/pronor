from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional


class Role(str, Enum):
    INSPECTOR = "pruefer"
    ADMIN = "admin"
    CUSTOMER = "kunde"


class TrafficLight(str, Enum):
    RED = "rot"
    YELLOW = "gelb"
    GREEN = "gruen"


class InvoiceStatus(str, Enum):
    OPEN = "offen"
    PARTIAL = "teilbezahlt"
    PAID = "bezahlt"
    OVERDUE = "ueberfaellig"


@dataclass
class User:
    user_id: str
    name: str
    role: Role
    email: str = ""


@dataclass
class Asset:
    asset_id: str
    name: str
    serial_number: str
    location: str
    asset_type: str


@dataclass
class InspectionPlan:
    plan_id: str
    asset_id: str
    regulation: str
    interval_days: int
    last_inspection: Optional[date] = None

    def next_due_date(self) -> date:
        if self.last_inspection is None:
            return date.today()
        return self.last_inspection + timedelta(days=self.interval_days)


@dataclass
class InspectionRecord:
    record_id: str
    plan_id: str
    inspector_id: str
    performed_on: date
    result: str
    findings: str
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Invoice:
    invoice_id: str
    customer: str
    amount_eur: float
    created_on: date
    status: InvoiceStatus = InvoiceStatus.OPEN
    paid_amount_eur: float = 0.0
    due_date: Optional[date] = None
    source_record_ids: List[str] = field(default_factory=list)


class ComplianceBillingPlatform:
    def __init__(self) -> None:
        self.users: Dict[str, User] = {}
        self.assets: Dict[str, Asset] = {}
        self.plans: Dict[str, InspectionPlan] = {}
        self.records: Dict[str, InspectionRecord] = {}
        self.invoices: Dict[str, Invoice] = {}

    def add_user(self, user: User) -> None:
        self.users[user.user_id] = user

    def add_asset(self, asset: Asset) -> None:
        self.assets[asset.asset_id] = asset

    def add_plan(self, plan: InspectionPlan) -> None:
        if plan.asset_id not in self.assets:
            raise ValueError("Asset nicht gefunden")
        self.plans[plan.plan_id] = plan

    def record_inspection(self, record: InspectionRecord) -> None:
        plan = self.plans.get(record.plan_id)
        if plan is None:
            raise ValueError("Pruefplan nicht gefunden")
        if record.inspector_id not in self.users:
            raise ValueError("Pruefer nicht gefunden")
        self.records[record.record_id] = record
        plan.last_inspection = record.performed_on

    def merge_record(self, incoming: InspectionRecord) -> str:
        existing = self.records.get(incoming.record_id)
        if not existing:
            self.record_inspection(incoming)
            return "created"
        if incoming.updated_at > existing.updated_at:
            self.record_inspection(incoming)
            return "updated"
        return "ignored"

    def create_invoice(
        self,
        invoice_id: str,
        customer: str,
        record_ids: List[str],
        price_per_inspection: float,
    ) -> Invoice:
        valid_ids = [record_id for record_id in record_ids if record_id in self.records]
        amount = round(len(valid_ids) * price_per_inspection, 2)
        invoice = Invoice(
            invoice_id=invoice_id,
            customer=customer,
            amount_eur=amount,
            created_on=date.today(),
            due_date=date.today() + timedelta(days=14),
            source_record_ids=valid_ids,
        )
        self.invoices[invoice_id] = invoice
        return invoice

    def update_invoice_payment(self, invoice_id: str, payment_amount: float) -> Invoice:
        invoice = self.invoices[invoice_id]
        invoice.paid_amount_eur = round(invoice.paid_amount_eur + payment_amount, 2)
        if invoice.paid_amount_eur <= 0:
            invoice.status = InvoiceStatus.OPEN
        elif invoice.paid_amount_eur < invoice.amount_eur:
            invoice.status = InvoiceStatus.PARTIAL
        else:
            invoice.status = InvoiceStatus.PAID
        return invoice

    def refresh_invoice_states(self) -> None:
        today = date.today()
        for inv in self.invoices.values():
            if inv.status != InvoiceStatus.PAID and inv.due_date and inv.due_date < today:
                if inv.paid_amount_eur <= 0:
                    inv.status = InvoiceStatus.OVERDUE
                elif inv.paid_amount_eur < inv.amount_eur:
                    inv.status = InvoiceStatus.PARTIAL

    def due_reminders(self, horizon_days: int = 14) -> List[str]:
        reminders: List[str] = []
        today = date.today()
        for plan in self.plans.values():
            due = plan.next_due_date()
            days = (due - today).days
            if days <= horizon_days:
                asset = self.assets[plan.asset_id]
                reminders.append(
                    f"Pruefung faellig: {asset.name} ({plan.regulation}) am {due.isoformat()}"
                )
        return sorted(reminders)

    def escalation_reminders(self) -> List[Dict[str, str]]:
        out = []
        today = date.today()
        levels = {7: "Stufe 1", 3: "Stufe 2", 1: "Stufe 3"}
        for plan in self.plans.values():
            due = plan.next_due_date()
            days = (due - today).days
            asset = self.assets[plan.asset_id]
            if days in levels:
                out.append(
                    {
                        "level": levels[days],
                        "message": f"{asset.name} in {days} Tagen faellig ({plan.regulation})",
                    }
                )
            if days < 0:
                out.append(
                    {
                        "level": "Eskaliert",
                        "message": f"{asset.name} ist ueberfaellig seit {-days} Tagen",
                    }
                )
        return out

    def datev_export_rows(self) -> List[Dict[str, str]]:
        self.refresh_invoice_states()
        rows = []
        for inv in self.invoices.values():
            rows.append(
                {
                    "rechnung": inv.invoice_id,
                    "kunde": inv.customer,
                    "betrag": f"{inv.amount_eur:.2f}",
                    "bezahlt": f"{inv.paid_amount_eur:.2f}",
                    "status": inv.status.value,
                    "faellig": inv.due_date.isoformat() if inv.due_date else "",
                }
            )
        return rows

    def dashboard(self) -> Dict[str, object]:
        self.refresh_invoice_states()
        today = date.today()
        due_items = []
        for plan in self.plans.values():
            due = plan.next_due_date()
            delta = (due - today).days
            if delta < 0:
                state = TrafficLight.RED
            elif delta <= 14:
                state = TrafficLight.YELLOW
            else:
                state = TrafficLight.GREEN
            due_items.append(
                {
                    "plan_id": plan.plan_id,
                    "asset": self.assets[plan.asset_id].name,
                    "regulation": plan.regulation,
                    "due_date": due.isoformat(),
                    "state": state.value,
                }
            )

        open_invoices = [inv for inv in self.invoices.values() if inv.status != InvoiceStatus.PAID]
        open_revenue = round(sum(inv.amount_eur - inv.paid_amount_eur for inv in open_invoices), 2)
        return {
            "due_inspections": sorted(due_items, key=lambda x: x["due_date"]),
            "open_invoices": len(open_invoices),
            "open_revenue_eur": open_revenue,
            "assets": len(self.assets),
            "inspection_records": len(self.records),
        }

    def to_dict(self) -> Dict[str, object]:
        return {
            "users": [{**asdict(u), "role": u.role.value} for u in self.users.values()],
            "assets": [asdict(a) for a in self.assets.values()],
            "plans": [
                {
                    **asdict(p),
                    "last_inspection": p.last_inspection.isoformat() if p.last_inspection else None,
                }
                for p in self.plans.values()
            ],
            "records": [
                {
                    **asdict(r),
                    "performed_on": r.performed_on.isoformat(),
                    "updated_at": r.updated_at.isoformat(),
                }
                for r in self.records.values()
            ],
            "invoices": [
                {
                    **asdict(i),
                    "created_on": i.created_on.isoformat(),
                    "due_date": i.due_date.isoformat() if i.due_date else None,
                    "status": i.status.value,
                }
                for i in self.invoices.values()
            ],
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "ComplianceBillingPlatform":
        p = cls()
        for u in payload.get("users", []):
            p.add_user(User(u["user_id"], u["name"], Role(u["role"]), u.get("email", "")))
        for a in payload.get("assets", []):
            p.add_asset(Asset(**a))
        for plan in payload.get("plans", []):
            p.add_plan(
                InspectionPlan(
                    plan["plan_id"],
                    plan["asset_id"],
                    plan["regulation"],
                    int(plan["interval_days"]),
                    date.fromisoformat(plan["last_inspection"]) if plan.get("last_inspection") else None,
                )
            )
        for r in payload.get("records", []):
            p.record_inspection(
                InspectionRecord(
                    r["record_id"],
                    r["plan_id"],
                    r["inspector_id"],
                    date.fromisoformat(r["performed_on"]),
                    r["result"],
                    r["findings"],
                    datetime.fromisoformat(r.get("updated_at", datetime.utcnow().isoformat())),
                )
            )
        for i in payload.get("invoices", []):
            p.invoices[i["invoice_id"]] = Invoice(
                invoice_id=i["invoice_id"],
                customer=i["customer"],
                amount_eur=float(i["amount_eur"]),
                created_on=date.fromisoformat(i["created_on"]),
                status=InvoiceStatus(i.get("status", "offen")),
                paid_amount_eur=float(i.get("paid_amount_eur", 0.0)),
                due_date=date.fromisoformat(i["due_date"]) if i.get("due_date") else None,
                source_record_ids=list(i.get("source_record_ids", [])),
            )
        return p


class TenantStorage:
    def __init__(self, base_dir: str = "data") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def load(self, tenant_id: str) -> ComplianceBillingPlatform:
        path = self.base_dir / f"{tenant_id}.json"
        if not path.exists():
            return ComplianceBillingPlatform()
        return ComplianceBillingPlatform.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def save(self, tenant_id: str, platform: ComplianceBillingPlatform) -> None:
        path = self.base_dir / f"{tenant_id}.json"
        path.write_text(json.dumps(platform.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")


def demo() -> None:
    p = ComplianceBillingPlatform()
    p.add_user(User("u1", "Maja", Role.INSPECTOR))
    p.add_asset(Asset("a1", "Schaltschrank A", "SN-001", "Werk 1", "Elektroanlage"))
    p.add_plan(InspectionPlan("p1", "a1", "DGUV V3", 180))
    p.record_inspection(InspectionRecord("r1", "p1", "u1", date.today(), "bestanden", "Keine Maengel"))
    p.create_invoice("i1", "Muster GmbH", ["r1"], 149)
    print(p.dashboard())


if __name__ == "__main__":
    demo()