// @vitest-environment jsdom
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppUpdater } from "./AppUpdater";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke, isTauri: () => true }));

describe("application updates", () => {
  beforeEach(() => {
    vi.stubEnv("DEV", false);
    invoke.mockReset();
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.unstubAllEnvs();
  });

  it("checks automatically without installing, and disables installation during a scan", async () => {
    vi.useFakeTimers();
    invoke.mockResolvedValue({ version: "2.0.4", notes: "Update" });
    const run = vi.fn();
    const view = render(
      <AppUpdater locked={false} run={run} page="connection" />,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(invoke).toHaveBeenCalledExactlyOnceWith("check_update");
    expect(screen.getByText("Version 2.0.4 disponible")).toBeTruthy();
    expect(run).not.toHaveBeenCalled();
    view.rerender(<AppUpdater locked run={run} page="scan" />);
    expect(
      (screen.getByText("Installer la mise à jour") as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6 * 60 * 60 * 1000);
    });
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("requires confirmation and runs installation through the shared operation lock", async () => {
    invoke
      .mockResolvedValueOnce({ version: "2.0.4", notes: "" })
      .mockResolvedValue(undefined);
    const run = vi.fn(async (_title: string, task: () => Promise<void>) =>
      task(),
    );
    render(<AppUpdater locked={false} run={run} page="settings" />);
    fireEvent.click(screen.getByText("Vérifier les mises à jour"));
    fireEvent.click(await screen.findByText("Installer la mise à jour"));
    expect(invoke).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText("Télécharger et installer"));
    expect(run).toHaveBeenCalledWith(
      "Mise à jour de l’application",
      expect.any(Function),
    );
    expect(invoke).toHaveBeenLastCalledWith("install_update", {
      version: "2.0.4",
    });
  });

  it("shows check errors without offering installation", async () => {
    invoke.mockRejectedValue(new Error("GitHub indisponible"));
    render(<AppUpdater locked={false} run={vi.fn()} page="settings" />);
    fireEvent.click(screen.getByText("Vérifier les mises à jour"));
    expect(await screen.findByText("Error: GitHub indisponible")).toBeTruthy();
    expect(screen.queryByText("Installer la mise à jour")).toBeNull();
  });
});
