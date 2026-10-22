// @vitest-environment jsdom
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ComponentProps } from "react";
import { TweaksPage } from "./TweaksPage";
import type { Scan, TweakStatus } from "../types";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
afterEach(() => {
  cleanup();
  invoke.mockReset();
});

const scan = {
  scan_id: 1,
  demo: false,
  cancelled: false,
  device: { serial: "phone", state: "device", model: "Test" },
  interventions: [],
} as unknown as Scan;
const status: TweakStatus = {
  dns: null,
  chrome: true,
  samsung: null,
  default_browser: null,
  home: null,
  one_ui_available: false,
  warnings: [],
  mupdf: null,
  pdf_handler: null,
};
function setup(
  value = status,
  overrides: Partial<ComponentProps<typeof TweaksPage>> = {},
) {
  invoke.mockImplementation(async (command: string) =>
    command === "tweaks_status"
      ? value
      : { scan, error: null, message: "Intervention inscrite" },
  );
  const props: ComponentProps<typeof TweaksPage> = {
    scan,
    device: scan.device,
    locked: false,
    run: vi.fn(async (_title, task) => {
      await task();
    }),
    setScan: vi.fn(),
    setError: vi.fn(),
    setNotice: vi.fn(),
    scanNow: vi.fn(),
    navigate: vi.fn(),
    ...overrides,
  };
  const view = render(<TweaksPage {...props} />);
  return { props, view };
}
const button = (name: string) =>
  screen.getByRole("button", { name }) as HTMLButtonElement;

describe("MuPDF workshop flow", () => {
  it("offers official installation but blocks PDF selection and verification when absent", async () => {
    setup();
    await screen.findByRole("button", { name: "Installer MuPDF (Play Store)" });
    expect(button("Choisir MuPDF pour les PDF").disabled).toBe(true);
    expect(button("Vérifier le choix MuPDF").disabled).toBe(true);
    fireEvent.click(button("Installer MuPDF (Play Store)"));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("apply_tweak", {
        serial: "phone",
        scanId: 1,
        action: "mupdf_store",
        note: "",
      }),
    );
  });
  it("allows guided selection and a separate verification for an active MuPDF", async () => {
    const { props, view } = setup({
      ...status,
      mupdf: true,
      pdf_handler: "com.old.reader",
    });
    await waitFor(() =>
      expect(button("Choisir MuPDF pour les PDF").disabled).toBe(false),
    );
    expect(button("Réglages de l’ancien lecteur").disabled).toBe(false);
    fireEvent.click(button("Vérifier le choix MuPDF"));
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("apply_tweak", {
        serial: "phone",
        scanId: 1,
        action: "pdf_verify",
        note: "",
      }),
    );
    view.rerender(<TweaksPage {...props} locked />);
    expect(button("Vérifier le choix MuPDF").disabled).toBe(true);
    expect(button("Choisir MuPDF pour les PDF").disabled).toBe(true);
  });
  it.each([
    { ...scan, demo: true },
    { ...scan, device: { ...scan.device, state: "historical" } },
    { ...scan, device: { ...scan.device, serial: "other-phone" } },
  ])("does not operate outside the same live scan", (ineligibleScan) => {
    setup(status, { scan: ineligibleScan });
    expect(button("Fiche MuPDF (Play Store)").disabled).toBe(true);
    expect(invoke).not.toHaveBeenCalled();
  });
});
