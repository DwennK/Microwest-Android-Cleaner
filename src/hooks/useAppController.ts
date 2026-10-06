import { invoke, isTauri } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";
import { defaultFilters, noDevice, type PageId } from "../app-config";
import { filteredRows, protectedRow, type Filters } from "../lib/triage";
import type {
  Boot,
  Detection,
  Device,
  HistoryEntry,
  Scan,
  Settings,
} from "../types";
import { useOperation } from "./useOperation";
export function useAppController() {
  const [page, setPage] = useState<PageId>("connection");
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [page]);
  const [boot, setBoot] = useState<Boot | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [device, setDevice] = useState<Device>(noDevice);
  const [serial, setSerial] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [scan, setScan] = useState<Scan | null>(null);
  const [includeSystem, setIncludeSystem] = useState(false);
  const {
    busy,
    busyRef,
    progress,
    error,
    setError,
    notice,
    setNotice,
    run,
    cancel,
  } = useOperation();
  const [diagnostic, setDiagnostic] = useState("");
  const [filters, setFilters] = useState(defaultFilters);
  const [selected, setSelected] = useState<string[]>([]);
  const [detail, setDetail] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [report, setReport] = useState("");
  const [aiConfirm, setAiConfirm] = useState(false);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [apiKey, setApiKey] = useState("");
  const connected = device.state === "device";
  const available = isTauri() && !!boot;
  const rows = scan?.rows ?? [];
  const visible = filteredRows(rows, filters);
  const detailRow = rows.find((r) => r.app.package_name === detail);
  const high = rows.filter(
    (r) => r.risk.score >= 60 && !protectedRow(r),
  ).length;
  const review = rows.filter(
    (r) => r.risk.recommended_action === "review",
  ).length;
  const locked = !!busy || !available;
  const acceptScan = (value: Scan) => {
    setScan(value);
    setSelected([]);
    setDetail(null);
  };
  const detect = useCallback(async (target: string) => {
    const d = await invoke<Detection>("detect_devices", { serial: target });
    setDevices(d.devices);
    setDevice(d.device);
  }, []);
  useEffect(() => {
    let active = true;
    if (!isTauri()) {
      setError(
        "Interface de prévisualisation : les fonctions système nécessitent l’application desktop. Lancez npm run tauri dev.",
      );
      return;
    }
    invoke<Boot>("bootstrap")
      .then(async (b) => {
        if (!active) return;
        setBoot(b);
        setSettings(b.settings);
        setScan(b.scan);
        if (b.settings_error) setError(b.settings_error);
        if (b.migration_backup)
          setNotice(`Base locale migrée. Sauvegarde : ${b.migration_backup}`);
        await detect("");
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, [detect, setError, setNotice]);
  useEffect(() => {
    if (!available || !autoRefresh) return;
    let refreshing = false;
    const timer = window.setInterval(() => {
      if (busyRef.current || refreshing) return;
      refreshing = true;
      detect(serial)
        .catch((e) => {
          setDevice({ ...noDevice, message: String(e) });
        })
        .finally(() => {
          refreshing = false;
        });
    }, 8000);
    return () => clearInterval(timer);
  }, [available, serial, detect, autoRefresh, busyRef]);
  const refreshHistory = async () =>
    setHistory(await invoke<HistoryEntry[]>("history"));
  const navigate = (id: PageId) => {
    setPage(id);
    if (id === "exports" && available)
      void run("Lecture de l’historique", refreshHistory);
  };
  const scanNow = () =>
    void run("Scan du téléphone", async () => {
      setPage("scan");
      setScan(null);
      setSelected([]);
      const result = await invoke<Scan>("start_scan", {
        serial: device.serial,
        includeSystem,
      });
      acceptScan(result);
      setPage("results");
      setNotice(
        result.cancelled
          ? "Scan interrompu. Résultats partiels, aucune suppression autorisée."
          : `${result.rows.length} applications analysées. Le scan est enregistré localement.`,
      );
    });
  const updateRow = (command: string, args: Record<string, unknown>) =>
    void run("Enregistrement", async () => {
      setScan(await invoke<Scan>(command, args));
      setNotice("Enregistré dans la base locale.");
    });
  const exportScan = (kind: string) =>
    void run("Création du rapport", async () => {
      const p = await invoke<string>("export_scan", { kind, selected });
      setReport(p);
      setNotice(`Export créé : ${p}`);
    });
  const copy = (text: string) => navigator.clipboard.writeText(text);
  const toggle = (p: string) =>
    setSelected((s) => (s.includes(p) ? s.filter((v) => v !== p) : [...s, p]));
  const changeFilter = <K extends keyof Filters>(key: K, value: Filters[K]) =>
    setFilters((f) => ({ ...f, [key]: value }));
  return {
    cancel,
    page,
    navigate,
    rows,
    connected,
    device,
    locked,
    scanNow,
    error,
    setError,
    notice,
    setNotice,
    busy,
    progress,
    scan,
    serial,
    setSerial,
    run,
    detect,
    devices,
    autoRefresh,
    setAutoRefresh,
    setPage,
    setDiagnostic,
    setDevices,
    setDevice,
    diagnostic,
    copy,
    setReport,
    includeSystem,
    setIncludeSystem,
    high,
    review,
    selected,
    setAiConfirm,
    filters,
    changeFilter,
    setSelected,
    visible,
    setFilters,
    setDetail,
    toggle,
    setScan,
    exportScan,
    report,
    refreshHistory,
    history,
    acceptScan,
    settings,
    apiKey,
    setSettings,
    setApiKey,
    boot,
    detailRow,
    updateRow,
    aiConfirm,
  };
}
export type AppController = ReturnType<typeof useAppController>;
