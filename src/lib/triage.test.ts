import { describe, expect, it } from "vitest";
import { filteredRows, liveScan, removable, type Filters } from "./triage";
import type { Row, Scan } from "../types";
import cases from "../../src-tauri/reference/risk-cases.json";
const base = cases[50];
const makeRow = (): Row => ({
  app: base.app,
  risk: base.risk,
  local_risk: base.risk,
  ai: null,
  ai_text: "",
  note: "",
  validation: "unreviewed",
});
const filters: Filters = {
  search: "",
  action: "",
  min: 0,
  permission: "",
  visibility: "",
  sort: "risk",
};
describe("Sélection et filtres atelier", () => {
  it("ne sélectionne jamais les apps système, conservées, retirées ou incomplètes", () => {
    const r = makeRow();
    r.app = { ...r.app, is_system_app: false, dumpsys_error: "" };
    r.risk = { ...r.risk, recommended_action: "review" };
    expect(removable(r)).toBe(true);
    for (const status of ["keep", "removed"])
      expect(removable({ ...r, validation: status })).toBe(false);
    expect(removable({ ...r, app: { ...r.app, is_system_app: true } })).toBe(
      false,
    );
    expect(
      removable({ ...r, app: { ...r.app, dumpsys_error: "offline" } }),
    ).toBe(false);
    expect(
      removable({
        ...r,
        risk: { ...r.risk, recommended_action: "do_not_touch" },
      }),
    ).toBe(false);
  });
  it("combine recherche, provenance et permission sans modifier le scan", () => {
    const r = makeRow();
    r.app = {
      ...r.app,
      app_label: "Reader",
      installer: "com.android.vending",
      has_overlay: true,
    };
    r.note = "Client demande examen";
    expect(
      filteredRows([r], {
        ...filters,
        search: "CLIENT",
        permission: "OVERLAY",
      }),
    ).toHaveLength(1);
    expect(
      filteredRows([r], { ...filters, visibility: "sideload" }),
    ).toHaveLength(0);
    expect(filteredRows([r], { ...filters, search: "absent" })).toHaveLength(0);
    expect(r.note).toBe("Client demande examen");
  });
  it("refuse les scans historiques, incomplets et démonstrations pour suppression", () => {
    const s = {
      scan_id: 1,
      device: { serial: "A", state: "device" },
      demo: false,
      cancelled: false,
    } as Scan;
    expect(liveScan(s)).toBe(true);
    expect(liveScan({ ...s, demo: true })).toBe(false);
    expect(liveScan({ ...s, cancelled: true })).toBe(false);
    expect(
      liveScan({ ...s, device: { ...s.device, state: "historical" } }),
    ).toBe(false);
    expect(liveScan(null)).toBe(false);
  });
});
