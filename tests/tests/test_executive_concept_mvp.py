import json
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app import (
    build_ai_answer,
    build_risk_snapshot,
    cost_of_inaction,
    create_due_offer,
    execute_ai_action,
    generate_route_plan,
    hash_password,
    verify_password,
    haversine_km,
    parse_lat_lng,
    filter_assets_in_radius,
    parse_csv_rows,
    render_pdf_report,
    sign_jwt,
    suggest_asset_from_photo,
    verify_jwt,
    validate_template_requirements,
    save_json_file,
    load_compliance_templates,
    recurring_invoice_run,
    sla_monitor,
    tenant_health_score,
    lost_revenue_list,
    explain_red_items,
    SUBSCRIPTIONS_DIR,
    TEMPLATES_DIR,
    CONTRACTS_DIR,
)
from executive_concept_mvp import (
    Asset,
    ComplianceBillingPlatform,
    InspectionPlan,
    InspectionRecord,
    InvoiceStatus,
    Role,
    TenantStorage,
    User,
)


def test_end_to_end_flow_updates_dashboard_and_invoice():
    p = ComplianceBillingPlatform()
    p.add_user(User("u1", "Alex", Role.INSPECTOR))
    p.add_asset(Asset("a1", "Maschine", "SN1", "Standort", "Hebezeug"))
    p.add_plan(InspectionPlan("p1", "a1", "TRBS", interval_days=365))
    p.record_inspection(InspectionRecord("r1", "p1", "u1", date.today(), "bestanden", "OK"))
    p.create_invoice("i1", "Kunde", ["r1"], 99.0)
    dashboard = p.dashboard()
    assert dashboard["open_invoices"] == 1
    assert dashboard["open_revenue_eur"] == 99.0


def test_tenant_storage_roundtrip_with_updated_at(tmp_path):
    s = TenantStorage(base_dir=str(tmp_path))
    p = ComplianceBillingPlatform()
    p.add_user(User("u1", "Nina", Role.ADMIN))
    p.add_asset(Asset("a1", "Pumpe", "SN-7", "Halle", "Maschine"))
    p.add_plan(InspectionPlan("p1", "a1", "DGUV V3", 180))
    p.record_inspection(InspectionRecord("r1", "p1", "u1", date.today(), "bestanden", "ok"))
    s.save("kunde-a", p)
    loaded = s.load("kunde-a")
    assert loaded.records["r1"].updated_at


def test_merge_strategy_and_invoice_status():
    p = ComplianceBillingPlatform()
    p.add_user(User("u1", "Alex", Role.INSPECTOR))
    p.add_asset(Asset("a1", "M", "S", "L", "T"))
    p.add_plan(InspectionPlan("p1", "a1", "DGUV", 180))

    old = InspectionRecord("r1", "p1", "u1", date.today(), "bestanden", "v1", datetime.utcnow())
    assert p.merge_record(old) == "created"
    newer = InspectionRecord("r1", "p1", "u1", date.today(), "bestanden", "v2", datetime.utcnow() + timedelta(seconds=5))
    assert p.merge_record(newer) == "updated"

    p.create_invoice("i1", "K", ["r1"], 100)
    p.update_invoice_payment("i1", 40)
    assert p.invoices["i1"].status == InvoiceStatus.PARTIAL


def test_helpers_csv_hash_pdf_and_jwt():
    rows = parse_csv_rows("asset_id,name,serial_number,location,asset_type\na1,Motor,SN1,Werk,Elektro")
    assert rows[0]["name"] == "Motor"
    hashed = hash_password("secret")
    assert verify_password("secret", hashed)
    pdf = render_pdf_report(InspectionRecord("r1", "p1", "u1", date.today(), "ok", "none"), "tenant")
    assert pdf.startswith(b"%PDF")
    token = sign_jwt({"tenant": "t1", "exp": 9999999999})
    assert verify_jwt(token)["tenant"] == "t1"


def test_dashboard_ampelsystem_states():
    p = ComplianceBillingPlatform()
    p.add_asset(Asset("a1", "Altanlage", "S1", "L1", "T"))
    p.add_asset(Asset("a2", "Baldfaellig", "S2", "L1", "T"))
    p.add_asset(Asset("a3", "Neu", "S3", "L1", "T"))

    p.add_plan(InspectionPlan("p1", "a1", "DGUV", 180, date.today() - timedelta(days=190)))
    p.add_plan(InspectionPlan("p2", "a2", "DGUV", 180, date.today() - timedelta(days=170)))
    p.add_plan(InspectionPlan("p3", "a3", "DGUV", 180, date.today() - timedelta(days=10)))

    by_plan = {item["plan_id"]: item["state"] for item in p.dashboard()["due_inspections"]}
    assert by_plan["p1"] == "rot"
    assert by_plan["p2"] == "gelb"
    assert by_plan["p3"] == "gruen"


def test_ai_answer_uses_dashboard_context():
    p = ComplianceBillingPlatform()
    p.add_user(User("u1", "Alex", Role.INSPECTOR))
    p.add_asset(Asset("a1", "Maschine", "SN1", "Standort", "Hebezeug"))
    p.add_plan(InspectionPlan("p1", "a1", "TRBS", interval_days=365))
    p.record_inspection(InspectionRecord("r1", "p1", "u1", date.today(), "bestanden", "OK"))
    p.create_invoice("i1", "Kunde", ["r1"], 99.0)

    answer = build_ai_answer("Wie viele offene Rechnungen gibt es?", p)
    assert "offene Rechnungen" in answer
    assert "99.00" in answer


def test_ai_action_can_create_asset_plan_and_batch():
    p = ComplianceBillingPlatform()
    p.add_user(User("ins1", "Inspector", Role.INSPECTOR))
    auth = {"tenant1": {"users": []}}

    def next_id(prefix, existing):
        i = 1
        while f"{prefix}{i}" in existing:
            i += 1
        return f"{prefix}{i}"

    msg, changed = execute_ai_action("anlage:Kesselhaus|Werk Nord|Druckanlage", p, auth, "tenant1", next_id)
    assert changed and "angelegt" in msg
    asset_id = next(iter(p.assets.keys()))

    msg, changed = execute_ai_action(f"pruefplan:{asset_id}|TRBS|180", p, auth, "tenant1", next_id)
    assert changed and "Prüfplan" in msg

    msg, changed = execute_ai_action("batchpruefung:ins1|Muster GmbH|120", p, auth, "tenant1", next_id)
    assert changed and "Batch" in msg
    assert len(p.records) == 1
    assert len(p.invoices) == 1

    invoice_id = next(iter(p.invoices.keys()))
    msg, changed = execute_ai_action(f"zahlung:{invoice_id}|120", p, auth, "tenant1", next_id)
    assert changed and "Status" in msg
    assert p.invoices[invoice_id].status.value == "bezahlt"


def test_automation_helpers_route_offer_risk_and_photo_suggestion():
    p = ComplianceBillingPlatform()
    p.add_user(User("ins1", "Inspector", Role.INSPECTOR))
    p.add_asset(Asset("a1", "Schrank", "SN1", "Werk Nord", "Elektroanlage"))
    p.add_plan(InspectionPlan("p1", "a1", "DGUV V3", 180))
    p.create_invoice("i1", "Kunde", [], 100)

    route = generate_route_plan(p)
    assert route and route[0]["inspector"] == "ins1"

    offer = create_due_offer(p, horizon_days=30)
    assert offer["count"] >= 1

    risk = build_risk_snapshot(p)
    assert "risk_score" in risk

    assert suggest_asset_from_photo("kran_foto.jpg") == ("Hebezeug", "TRBS")
    assert cost_of_inaction(p) >= 0


def test_ai_extended_workflows():
    p = ComplianceBillingPlatform()
    p.add_user(User("pr1", "Pruefer", Role.INSPECTOR))
    auth = {"tenant-x": {"users": []}}

    def next_id(prefix, existing):
        i = 1
        while f"{prefix}{i}" in existing:
            i += 1
        return f"{prefix}{i}"

    msg, changed = execute_ai_action("komplettauftrag:KundeX|Werk 1|2|180|pr1", p, auth, "tenant-x", next_id)
    assert changed and "Komplettauftrag" in msg

    first_plan = next(iter(p.plans.keys()))
    p.record_inspection(InspectionRecord("r999", first_plan, "pr1", date.today(), "bestanden", "Mangel A, Mangel B"))
    msg, changed = execute_ai_action("massnahmen:r999|teamleiter", p, auth, "tenant-x", next_id)
    assert changed and "Maßnahmenplan" in msg

    msg, changed = execute_ai_action("abrechnungsvorschlag:KundeX|99", p, auth, "tenant-x", next_id)
    assert changed and "Rechnung" in msg

    msg, changed = execute_ai_action("foto:schrank-elektro.jpg|Werk 2", p, auth, "tenant-x", next_id)
    assert changed and "Foto-Vorschlag" in msg


def test_template_validation_and_recurring_and_health(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = ComplianceBillingPlatform()
    p.add_user(User("ins1", "Inspector", Role.INSPECTOR))
    p.add_asset(Asset("a1", "Alt", "SN1", "Werk", "Elektroanlage"))
    p.add_plan(InspectionPlan("p1", "a1", "DGUV V3", 180, date.today() - timedelta(days=200)))
    p.record_inspection(InspectionRecord("r1", "p1", "ins1", date.today(), "bestanden", "ok"))

    save_json_file(TEMPLATES_DIR / "tenant1.json", {"kunde a": {"required_extra": "serienfoto"}})
    ok, _ = validate_template_requirements("tenant1", "kunde a", "img-1")
    assert ok is True
    ok, msg = validate_template_requirements("tenant1", "kunde a", "")
    assert ok is False and "serienfoto" in msg
    assert "kunde a" in load_compliance_templates("tenant1")

    save_json_file(CONTRACTS_DIR / "tenant1.json", {"sla_days": 7})
    sla = sla_monitor(p, "tenant1")
    assert sla["sla_days"] == 7
    assert sla["sla_risk_score"] >= 0

    save_json_file(SUBSCRIPTIONS_DIR / "tenant1.json", [{"customer": "Abo GmbH", "interval_days": 30, "amount": 299, "next_run": date.today().isoformat()}])
    created = recurring_invoice_run(p, "tenant1")
    assert len(created) == 1

    health = tenant_health_score(p, "tenant1")
    assert health >= 0
    lost = lost_revenue_list(p)
    assert lost and lost[0]["reason"] in {"keine Rechnung", "keine Prüfung"}
    assert isinstance(explain_red_items(p), list)

def test_geo_helpers_and_csv_delimiter():
    assert parse_lat_lng("52.1,13.4") == (52.1, 13.4)
    assert parse_lat_lng("x") is None
    dist = haversine_km(52.52, 13.405, 48.137, 11.575)
    assert dist > 400
    rows = parse_csv_rows("asset_id;name\na1;Anlage", delimiter=";")
    assert rows[0]["asset_id"] == "a1"
    filtered = filter_assets_in_radius((52.52, 13.4), [{"lat": 52.5, "lng": 13.42, "asset": "A"}], 10)
    assert len(filtered) == 1
