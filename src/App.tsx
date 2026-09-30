import { useCallback, useEffect, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Check,
  CheckCheck,
  ChevronRight,
  Clipboard,
  FileText,
  FolderOpen,
  History,
  Info,
  LoaderCircle,
  MonitorSmartphone,
  RefreshCw,
  ScanLine,
  Search,
  Settings2,
  ShieldCheck,
  ShieldQuestion,
  Smartphone,
  Sparkles,
  Square,
  Table2,
  Trash2,
  Unplug,
  X,
} from "lucide-react";
import { Button } from "./components/ui/button";
import { ConfirmDialog } from "./components/ui/alert-dialog";
import {
  actionLabels,
  filteredRows,
  liveScan,
  protectedRow,
  removable,
  safeInstallers,
  validationLabels,
  type Filters,
} from "./lib/triage";
import type {
  Boot,
  Detection,
  Device,
  HistoryEntry,
  Progress,
  Row,
  Scan,
  Settings,
} from "./types";

const navigation = [
  { id: "connection", label: "Connexion", icon: Smartphone },
  { id: "scan", label: "Analyse du téléphone", icon: ScanLine },
  { id: "results", label: "Applications", icon: Table2 },
  { id: "exports", label: "Rapports & historique", icon: FileText },
  { id: "settings", label: "Paramètres", icon: Settings2 },
];
const stateLabels: Record<string, string> = {
  device: "Connecté",
  unauthorized: "Autorisation requise",
  offline: "Hors ligne",
  disconnected: "Déconnecté",
  demo: "Démonstration",
  historical: "Historique",
};
const defaultFilters: Filters = {
  search: "",
  action: "",
  min: 0,
  permission: "",
  visibility: "",
  sort: "risk",
};
const noDevice: Device = {
  serial: "",
  state: "disconnected",
  details: "",
  model: "",
  manufacturer: "",
  android_version: "",
  message: "Connectez un téléphone Android pour commencer.",
};

function Badge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
function Empty({
  title,
  children,
  icon: Icon = ScanLine,
}: {
  title: string;
  children: React.ReactNode;
  icon?: typeof ScanLine;
}) {
  return (
    <div className="flex min-h-64 flex-col items-center justify-center px-8 py-12 text-center">
      <div className="mb-5 rounded-2xl bg-muted p-4 text-muted-foreground">
        <Icon size={28} strokeWidth={1.5} />
      </div>
      <h3 className="mb-2 font-semibold">{title}</h3>
      <div className="max-w-lg text-sm leading-6 text-muted-foreground">
        {children}
      </div>
    </div>
  );
}
function AppIcon({ row }: { row: Row }) {
  const [src, setSrc] = useState("");
  useEffect(() => {
    let active = true;
    setSrc("");
    if (row.app.icon_path && isTauri())
      invoke<string>("app_icon", { package: row.app.package_name })
        .then((v) => {
          if (active) setSrc(v);
        })
        .catch(() => {});
    return () => {
      active = false;
    };
  }, [row.app.package_name, row.app.icon_path]);
  return src ? (
    <img src={src} alt="" className="size-10 rounded-xl object-contain" />
  ) : (
    <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-lg font-semibold text-slate-500">
      {(row.app.app_label || row.app.package_name).slice(0, 1).toUpperCase()}
    </div>
  );
}

export default function App() {
  const [page, setPage] = useState("connection");
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
  const [busy, setBusy] = useState("");
  const busyRef = useRef(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
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

  const run = useCallback(async (title: string, task: () => Promise<void>) => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(title);
    setError("");
    setNotice("");
    setProgress(null);
    try {
      await task();
    } catch (e) {
      setError(String(e));
    } finally {
      busyRef.current = false;
      setBusy("");
    }
  }, []);
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
    const unlisten = listen<Progress>("operation-progress", (e) => {
      if (active) setProgress(e.payload);
    });
    return () => {
      active = false;
      void unlisten.then((f) => f());
    };
  }, [detect]);
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
  }, [available, serial, detect, autoRefresh]);
  const refreshHistory = async () =>
    setHistory(await invoke<HistoryEntry[]>("history"));
  const navigate = (id: string) => {
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

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="flex items-center gap-3 px-6 pb-9 pt-8">
          <div className="flex size-10 items-center justify-center rounded-xl bg-white text-xl font-black tracking-tighter text-[#0b2946]">
            M<span className="text-teal-600">.</span>
          </div>
          <div>
            <div className="text-lg font-bold tracking-tight text-white">
              Microwest
            </div>
            <div className="mt-0.5 text-[10px] tracking-widest text-slate-400">
              ANDROID CLEANER
            </div>
          </div>
        </div>
        <div className="eyebrow px-7 pb-3 text-slate-500">
          Espace technicien
        </div>
        <nav aria-label="Navigation principale" className="space-y-1 px-3">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-item ${page === id ? "active" : ""}`}
              onClick={() => navigate(id)}
            >
              <Icon size={18} strokeWidth={1.7} />
              <span>{label}</span>
              {id === "results" && rows.length > 0 && (
                <span className="ml-auto rounded bg-white/10 px-1.5 text-[10px]">
                  {rows.length}
                </span>
              )}
            </button>
          ))}
        </nav>
        <div className="mx-5 mt-auto rounded-xl border border-white/10 bg-white/5 p-4">
          <ShieldCheck size={20} className="mb-3 text-teal-300" />
          <div className="text-xs font-semibold text-white">
            Le technicien garde la main
          </div>
          <p className="mt-2 text-[11px] leading-5 text-slate-400">
            Métadonnées uniquement.
            <br />
            Chaque suppression exige une confirmation humaine.
          </p>
        </div>
        <div className="px-6 py-6 text-[10px] text-slate-500">
          MICROWEST · VERSION 2.0
          <br />
          <span className="text-slate-400">Shopy Phone Sàrl</span>
        </div>
      </aside>
      <div className="min-w-0">
        <header className="flex h-[76px] items-center justify-between border-b bg-white px-8">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span>Atelier</span>
            <ChevronRight size={13} />
            <span className="font-medium text-foreground">
              Diagnostic Android
            </span>
          </div>
          <div className="flex items-center gap-4">
            <Badge
              tone={
                connected
                  ? "good"
                  : device.state === "unauthorized"
                    ? "warn"
                    : "neutral"
              }
            >
              <span
                className={`size-1.5 rounded-full ${connected ? "bg-emerald-600" : "bg-slate-400"}`}
              />
              {stateLabels[device.state] || device.state}
            </Badge>
            <span className="max-w-52 truncate text-xs text-muted-foreground">
              {device.model || "Aucun téléphone"}
            </span>
          </div>
        </header>
        <main className="content">
          <div className="mb-7 flex items-start justify-between gap-4">
            <div>
              <div className="eyebrow mb-2 text-primary">
                {page === "connection"
                  ? "01 · Préparer"
                  : page === "scan"
                    ? "02 · Analyser"
                    : page === "results"
                      ? "03 · Examiner"
                      : page === "exports"
                        ? "04 · Restituer"
                        : "Configuration de l’atelier"}
              </div>
              <h1 className="text-[28px] font-semibold tracking-tight">
                {navigation.find((n) => n.id === page)?.label}
              </h1>
              <p className="mt-2 text-sm text-muted-foreground">
                {page === "connection"
                  ? "Connectez le téléphone et vérifiez son autorisation USB."
                  : page === "scan"
                    ? "Un diagnostic local des applications, sans accès aux données personnelles."
                    : page === "results"
                      ? "Examinez les signaux, validez les applications et décidez des actions."
                      : page === "exports"
                        ? "Un compte rendu clair pour le client et un historique pour l’atelier."
                        : "Outils locaux, analyse IA optionnelle et données de l’application."}
              </p>
            </div>
            {["results", "exports"].includes(page) && (
              <Button disabled={locked || !connected} onClick={scanNow}>
                <ScanLine />
                Nouveau scan
              </Button>
            )}
          </div>
          {error && (
            <div
              role="alert"
              className="mb-5 flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800"
            >
              <Info size={18} className="mt-0.5 shrink-0" />
              <span className="flex-1 whitespace-pre-wrap break-words">
                {error}
              </span>
              <button aria-label="Fermer l’erreur" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {notice && (
            <div
              role="status"
              className="mb-5 flex items-start gap-3 rounded-xl border border-teal-200 bg-teal-50 p-4 text-sm text-teal-900"
            >
              <Check size={18} className="shrink-0" />
              <span className="flex-1 break-all">{notice}</span>
              <button
                aria-label="Fermer le message"
                onClick={() => setNotice("")}
              >
                <X size={16} />
              </button>
            </div>
          )}
          {busy && (
            <div role="status" aria-live="polite" className="card mb-5 p-4">
              <div className="flex items-center gap-3">
                <LoaderCircle className="animate-spin text-primary" size={19} />
                <div className="flex-1">
                  <div className="text-sm font-semibold">{busy}</div>
                  <div className="mt-1 break-all text-xs text-muted-foreground">
                    {progress?.message || "Veuillez patienter…"}
                  </div>
                </div>
                {[
                  "Scan du téléphone",
                  "Analyse IA",
                  "Désinstallation",
                ].includes(busy) && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      void invoke("cancel_operation").catch((e) =>
                        setError(String(e)),
                      )
                    }
                  >
                    <Square />
                    Annuler
                  </Button>
                )}
              </div>
              {progress && progress.total > 0 && (
                <>
                  <progress
                    aria-label="Progression"
                    className="mt-4 h-1.5 w-full accent-teal-600"
                    max={progress.total}
                    value={progress.current}
                  />
                  <div className="mt-1 text-right text-[11px] text-muted-foreground">
                    {progress.current} / {progress.total}
                  </div>
                </>
              )}
            </div>
          )}
          {scan &&
            (scan.demo ||
              scan.cancelled ||
              scan.device.state === "historical") &&
            ["results", "exports"].includes(page) && (
              <div className="mb-5 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                {scan.demo
                  ? "DÉMONSTRATION · Applications et téléphone fictifs. Aucune opération sur un téléphone."
                  : scan.cancelled
                    ? "SCAN INCOMPLET · Ces résultats ne permettent aucune désinstallation."
                    : "HISTORIQUE · Consultation d’un scan enregistré. Relancez un scan réel pour intervenir sur le téléphone."}
              </div>
            )}

          {page === "connection" && (
            <div className="grid gap-6 xl:grid-cols-[1.45fr_1fr]">
              <section className="card overflow-hidden">
                <div className="flex items-center justify-between border-b p-6">
                  <h2 className="section-title">Téléphone connecté</h2>
                  <Badge tone={connected ? "good" : "neutral"}>
                    {connected ? "Prêt à analyser" : "En attente"}
                  </Badge>
                </div>
                <div className="p-7">
                  <div className="mb-7 flex items-center gap-6">
                    <div
                      className={`flex h-32 w-24 shrink-0 items-center justify-center rounded-2xl ${connected ? "bg-teal-50 text-primary" : "bg-slate-100 text-slate-400"}`}
                    >
                      <Smartphone size={64} strokeWidth={1} />
                    </div>
                    <div>
                      <h3 className="mb-2 text-xl font-semibold">
                        {device.model || "Aucun téléphone connecté"}
                      </h3>
                      <p className="max-w-md text-sm leading-6 text-muted-foreground">
                        {device.message}
                      </p>
                      {connected && (
                        <div className="mt-3 flex gap-2">
                          <Badge>{device.manufacturer}</Badge>
                          <Badge>
                            Android {device.android_version || "inconnu"}
                          </Badge>
                        </div>
                      )}
                    </div>
                  </div>
                  <label className="mb-2 block" htmlFor="device">
                    Appareil ADB
                  </label>
                  <select
                    id="device"
                    className="mb-5 w-full"
                    disabled={locked}
                    value={serial}
                    onChange={(e) => {
                      const value = e.target.value;
                      setSerial(value);
                      void run("Détection du téléphone", () => detect(value));
                    }}
                  >
                    <option value="">Auto · premier appareil autorisé</option>
                    {devices.map((d) => (
                      <option key={d.serial} value={d.serial}>
                        {d.serial} · {stateLabels[d.state] || d.state}
                      </option>
                    ))}
                    {serial && !devices.some((d) => d.serial === serial) && (
                      <option value={serial}>{serial} · déconnecté</option>
                    )}
                  </select>
                  <label className="mb-5 flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={autoRefresh}
                      disabled={locked}
                      onChange={(e) => setAutoRefresh(e.target.checked)}
                    />
                    Actualiser la connexion toutes les 8 secondes
                  </label>
                  <dl className="detail-grid border-t pt-5">
                    <dt>Numéro ADB</dt>
                    <dd className="font-mono text-xs">
                      {device.serial || "—"}
                    </dd>
                    <dt>Version Android</dt>
                    <dd>{device.android_version || "—"}</dd>
                    <dt>État</dt>
                    <dd>{stateLabels[device.state] || device.state}</dd>
                  </dl>
                  <div className="mt-7 flex flex-wrap gap-3">
                    <Button
                      disabled={locked}
                      onClick={() =>
                        void run("Détection du téléphone", () => detect(serial))
                      }
                    >
                      <RefreshCw />
                      Détecter le téléphone
                    </Button>
                    <Button
                      variant="outline"
                      disabled={locked || !connected}
                      onClick={() => setPage("scan")}
                    >
                      Préparer le scan
                      <ArrowRight />
                    </Button>
                  </div>
                </div>
              </section>
              <div className="space-y-6">
                <section className="card p-6">
                  <h2 className="section-title mb-5">Préparer la connexion</h2>
                  {[
                    "Déverrouiller le téléphone et activer les options développeur.",
                    "Activer « Débogage USB » et brancher un câble de données.",
                    "Accepter la demande d’autorisation RSA sur le téléphone.",
                  ].map((s, i) => (
                    <div key={s} className="mb-5 flex gap-3 last:mb-0">
                      <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold">
                        {i + 1}
                      </span>
                      <p className="text-sm leading-6 text-muted-foreground">
                        {s}
                      </p>
                    </div>
                  ))}
                </section>
                <section className="card p-6">
                  <h2 className="section-title mb-2">Outils de connexion</h2>
                  <p className="mb-5 text-xs leading-5 text-muted-foreground">
                    Utilisez la réparation si le téléphone reste hors ligne. Le
                    diagnostic rassemble les chemins, versions et états ADB.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      disabled={locked}
                      onClick={() =>
                        void run("Réparation ADB", async () => {
                          await invoke("daemon_action", { action: "repair" });
                          setAutoRefresh(true);
                          await detect(serial);
                          setNotice(
                            "Daemon ADB redémarré et appareils actualisés.",
                          );
                        })
                      }
                    >
                      <Unplug />
                      Réparer
                    </Button>
                    <Button
                      variant="outline"
                      disabled={locked}
                      onClick={() =>
                        void run("Diagnostic ADB", async () =>
                          setDiagnostic(
                            await invoke<string>("diagnostic", { serial }),
                          ),
                        )
                      }
                    >
                      <Activity />
                      Diagnostic
                    </Button>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {[
                      ["start", "Démarrer ADB"],
                      ["kill", "Arrêter ADB"],
                    ].map(([action, label]) => (
                      <Button
                        key={action}
                        variant="ghost"
                        size="sm"
                        disabled={locked}
                        onClick={() =>
                          void run(label, async () => {
                            const message = await invoke<string>(
                              "daemon_action",
                              { action },
                            );
                            if (action === "kill") {
                              setAutoRefresh(false);
                              setDevices([]);
                              setDevice(noDevice);
                            } else {
                              setAutoRefresh(true);
                              await detect(serial);
                            }
                            setNotice(message || `${label} : terminé`);
                          })
                        }
                      >
                        {label}
                      </Button>
                    ))}
                  </div>
                </section>
              </div>
              {diagnostic && (
                <section className="card p-6 xl:col-span-2">
                  <div className="mb-4 flex items-center justify-between">
                    <h2 className="section-title">Diagnostic ADB</h2>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          void run("Copie du diagnostic", async () => {
                            await copy(diagnostic);
                            setNotice("Diagnostic copié.");
                          })
                        }
                      >
                        <Clipboard />
                        Copier
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={locked}
                        onClick={() =>
                          void run("Export du diagnostic", async () => {
                            const p = await invoke<string>("export_diagnostic");
                            setReport(p);
                            setNotice(`Diagnostic exporté : ${p}`);
                          })
                        }
                      >
                        <ArrowDownToLine />
                        Exporter
                      </Button>
                    </div>
                  </div>
                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-lg bg-slate-50 p-4 text-xs leading-6">
                    {diagnostic}
                  </pre>
                </section>
              )}
            </div>
          )}

          {page === "scan" && (
            <div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
              <section className="card p-8">
                <div className="mb-7 inline-flex rounded-2xl bg-teal-50 p-4 text-primary">
                  <ScanLine size={32} />
                </div>
                <h2 className="mb-3 text-2xl font-semibold">
                  Examiner les applications installées
                </h2>
                <p className="mb-7 max-w-xl text-sm leading-7 text-muted-foreground">
                  Le scan recueille l’identité des applications, leur provenance
                  et leurs accès Android. Les règles de l’atelier calculent
                  ensuite un score et proposent les applications à vérifier.
                </p>
                <div className="mb-6 rounded-xl border bg-slate-50 p-5">
                  <div className="flex items-center gap-3">
                    <Smartphone size={20} />
                    <div>
                      <div className="text-sm font-semibold">
                        {device.model || "Connectez un téléphone"}
                      </div>
                      <div className="mt-1 font-mono text-xs text-muted-foreground">
                        {device.serial || "Connexion ADB nécessaire"}
                      </div>
                    </div>
                    <Badge tone={connected ? "good" : "warn"}>
                      {stateLabels[device.state]}
                    </Badge>
                  </div>
                </div>
                <label className="mb-7 flex items-center gap-3">
                  <input
                    type="checkbox"
                    checked={includeSystem}
                    disabled={locked}
                    onChange={(e) => setIncludeSystem(e.target.checked)}
                  />
                  Inclure les applications système
                  <span className="font-normal text-muted-foreground">
                    (protégées)
                  </span>
                </label>
                <Button disabled={locked || !connected} onClick={scanNow}>
                  <ScanLine />
                  Lancer le scan complet
                </Button>
                <p className="mt-4 text-xs text-muted-foreground">
                  La durée dépend du nombre d’applications et de la vitesse USB.
                </p>
              </section>
              <div className="space-y-5">
                <section className="card p-6">
                  <h2 className="section-title mb-5">Ce qui est analysé</h2>
                  {[
                    "Package, version, installateur et date",
                    "Permissions demandées et accordées",
                    "Accessibilité, overlay et notifications actifs",
                    "Visibilité, rôle HOME, nom et icône APK",
                    "Réputation locale et règles de tri atelier",
                  ].map((s) => (
                    <div
                      className="mb-4 flex items-center gap-3 text-sm"
                      key={s}
                    >
                      <CheckCheck size={17} className="shrink-0 text-primary" />
                      {s}
                    </div>
                  ))}
                </section>
                <div className="rounded-xl bg-[#e8eef4] p-6">
                  <ShieldCheck className="mb-3 text-[#224c70]" />
                  <h3 className="mb-2 text-sm font-semibold">
                    Un scan ne supprime rien
                  </h3>
                  <p className="text-xs leading-6 text-muted-foreground">
                    Les scores sont des signaux à examiner. La décision finale
                    appartient au technicien. Aucun SMS, contact, photo ou
                    contenu de notification n’est consulté.
                  </p>
                </div>
              </div>
            </div>
          )}

          {page === "results" && (
            <>
              <div className="mb-6 grid grid-cols-4 gap-4">
                {[
                  {
                    label: "Applications analysées",
                    value: rows.length,
                    icon: Table2,
                    color: "text-slate-600",
                  },
                  {
                    label: "À traiter",
                    value: high,
                    icon: ShieldQuestion,
                    color: "text-rose-600",
                  },
                  {
                    label: "À vérifier",
                    value: review,
                    icon: Search,
                    color: "text-amber-600",
                  },
                  {
                    label: "Sélectionnées",
                    value: selected.length,
                    icon: CheckCheck,
                    color: "text-primary",
                  },
                ].map(({ label, value, icon: Icon, color }) => (
                  <div
                    className="card flex items-start justify-between p-5"
                    key={label}
                  >
                    <div>
                      <div className="mb-2 text-xs text-muted-foreground">
                        {label}
                      </div>
                      <div className="text-3xl font-semibold tracking-tight">
                        {value}
                      </div>
                    </div>
                    <Icon size={19} className={color} />
                  </div>
                ))}
              </div>
              {scan?.errors.length ? (
                <details className="mb-5 rounded-lg border border-amber-200 bg-amber-50 p-4 text-xs text-amber-900">
                  <summary className="cursor-pointer font-semibold">
                    {scan.errors.length} avertissement(s) de collecte
                  </summary>
                  <ul className="mt-3 max-h-44 overflow-auto space-y-2">
                    {scan.errors.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ul>
                </details>
              ) : null}
              <section className="card overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4">
                  <div>
                    <h2 className="section-title">
                      Inventaire des applications
                    </h2>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {scan
                        ? `${scan.device.model || "Téléphone"} · ${scan.scan_id ? `Scan #${scan.scan_id}` : "Non enregistré"}`
                        : "Aucun scan réalisé"}
                    </p>
                  </div>
                  <Button
                    variant="outline"
                    disabled={
                      locked ||
                      !scan ||
                      scan.demo ||
                      scan.cancelled ||
                      scan.device.state === "historical" ||
                      !rows.length
                    }
                    onClick={() => setAiConfirm(true)}
                  >
                    <Sparkles />
                    Analyse IA
                  </Button>
                </div>
                <div className="flex flex-wrap gap-3 border-b p-4">
                  <div className="relative min-w-60 flex-1">
                    <Search
                      size={16}
                      className="absolute left-3 top-3 text-muted-foreground"
                    />
                    <input
                      aria-label="Rechercher une application"
                      className="w-full !pl-10"
                      placeholder="Nom, package, installateur, note…"
                      value={filters.search}
                      onChange={(e) => changeFilter("search", e.target.value)}
                    />
                  </div>
                  <select
                    aria-label="Filtrer par action"
                    value={filters.action}
                    onChange={(e) => changeFilter("action", e.target.value)}
                  >
                    <option value="">Toutes les actions</option>
                    {Object.entries(actionLabels).map(([v, l]) => (
                      <option key={v} value={v}>
                        {l}
                      </option>
                    ))}
                  </select>
                  <select
                    aria-label="Filtrer par visibilité"
                    value={filters.visibility}
                    onChange={(e) => changeFilter("visibility", e.target.value)}
                  >
                    <option value="">Tous les profils</option>
                    <option value="hidden">Faible visibilité</option>
                    <option value="sideload">Sideload / inconnu</option>
                    <option value="home">Écran d’accueil</option>
                  </select>
                  <select
                    aria-label="Filtrer par permission"
                    value={filters.permission}
                    onChange={(e) => changeFilter("permission", e.target.value)}
                  >
                    <option value="">Toutes permissions</option>
                    {[
                      ["ACCESSIBILITY", "Accessibilité"],
                      ["NOTIFICATION", "Notifications"],
                      ["OVERLAY", "Overlay"],
                      ["DEVICE_ADMIN", "Administrateur"],
                      ["VPN", "VPN"],
                      ["SMS", "SMS"],
                      ["CONTACTS", "Contacts"],
                      ["USAGE", "Utilisation"],
                      ["INSTALL", "Installation"],
                    ].map(([v, l]) => (
                      <option key={v} value={v}>
                        {l}
                      </option>
                    ))}
                  </select>
                  <label className="flex items-center gap-2">
                    Score min.
                    <input
                      aria-label="Score minimum"
                      type="number"
                      min="0"
                      max="100"
                      className="w-18"
                      value={filters.min}
                      onChange={(e) =>
                        changeFilter(
                          "min",
                          Math.max(0, Math.min(100, Number(e.target.value))),
                        )
                      }
                    />
                  </label>
                  <select
                    aria-label="Trier les applications"
                    value={filters.sort}
                    onChange={(e) =>
                      changeFilter("sort", e.target.value as Filters["sort"])
                    }
                  >
                    <option value="risk">Score décroissant</option>
                    <option value="name">Nom A–Z</option>
                    <option value="installer">Installateur</option>
                  </select>
                </div>
                <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={!rows.length || !!busy}
                    onClick={() =>
                      setSelected(
                        visible
                          .filter((r) => r.risk.score >= 60 && removable(r))
                          .map((r) => r.app.package_name),
                      )
                    }
                  >
                    <CheckCheck />
                    Cocher à traiter
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={!rows.length || !!busy}
                    onClick={() =>
                      setSelected(
                        visible
                          .filter(
                            (r) =>
                              r.risk.recommended_action === "review" &&
                              removable(r),
                          )
                          .map((r) => r.app.package_name),
                      )
                    }
                  >
                    Cocher à vérifier
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={!selected.length || !!busy}
                    onClick={() => setSelected([])}
                  >
                    Tout décocher
                  </Button>
                  <span className="ml-auto text-xs text-muted-foreground">
                    {visible.length} / {rows.length} applications
                  </span>
                </div>
                {rows.length === 0 ? (
                  <Empty
                    title={
                      scan
                        ? "Aucune application dans ce scan"
                        : "Votre inventaire apparaîtra ici"
                    }
                  >
                    Lancez un scan depuis un téléphone autorisé. Les résultats
                    ne sont jamais remplis avec des données fictives.
                  </Empty>
                ) : visible.length === 0 ? (
                  <Empty title="Aucune application ne correspond">
                    <Button
                      variant="outline"
                      onClick={() => setFilters(defaultFilters)}
                    >
                      Réinitialiser les filtres
                    </Button>
                  </Empty>
                ) : (
                  <div className="max-h-[570px] overflow-auto">
                    <table>
                      <thead className="sticky top-0 z-10">
                        <tr>
                          <th className="w-10">
                            <span className="sr-only">Sélection</span>
                          </th>
                          <th>Application</th>
                          <th>Score</th>
                          <th>Provenance</th>
                          <th>Action proposée</th>
                          <th>Validation</th>
                          <th>
                            <span className="sr-only">Détails</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {visible.map((r) => (
                          <tr
                            key={r.app.package_name}
                            className={
                              selected.includes(r.app.package_name)
                                ? "bg-teal-50/50"
                                : ""
                            }
                            onDoubleClick={() => setDetail(r.app.package_name)}
                          >
                            <td>
                              <input
                                aria-label={`Sélectionner ${r.app.app_label || r.app.package_name}`}
                                type="checkbox"
                                checked={selected.includes(r.app.package_name)}
                                disabled={!removable(r) || !!busy}
                                onChange={() => toggle(r.app.package_name)}
                              />
                            </td>
                            <td>
                              <button
                                className="flex items-center gap-3 text-left"
                                onClick={() => setDetail(r.app.package_name)}
                              >
                                <AppIcon row={r} />
                                <div>
                                  <div className="max-w-72 truncate font-semibold">
                                    {r.app.app_label || r.app.package_name}
                                  </div>
                                  <div className="mt-1 max-w-72 truncate font-mono text-[10px] text-muted-foreground">
                                    {r.app.package_name}
                                  </div>
                                  <div className="mt-1 flex gap-1">
                                    {r.app.has_launcher_entry === false && (
                                      <Badge tone="warn">Sans launcher</Badge>
                                    )}
                                    {r.app.is_default_home && (
                                      <Badge tone="warn">Accueil actif</Badge>
                                    )}
                                  </div>
                                </div>
                              </button>
                            </td>
                            <td>
                              <div className="flex items-center gap-2">
                                <span
                                  className={`text-base font-bold ${r.risk.score >= 60 ? "text-rose-700" : r.risk.score >= 30 ? "text-amber-700" : "text-emerald-700"}`}
                                >
                                  {r.risk.score}
                                </span>
                                <span className="text-[10px] text-muted-foreground">
                                  /100
                                </span>
                              </div>
                            </td>
                            <td>
                              <div
                                className="max-w-44 truncate text-xs"
                                title={r.app.installer}
                              >
                                {r.app.installer === "com.android.vending"
                                  ? "Google Play"
                                  : r.app.installer ===
                                      "com.sec.android.app.samsungapps"
                                    ? "Galaxy Store"
                                    : r.app.installer || "Inconnue"}
                              </div>
                              <div className="mt-1 text-[10px] text-muted-foreground">
                                {r.app.is_system_app
                                  ? "Système"
                                  : safeInstallers.includes(r.app.installer)
                                    ? "Source connue"
                                    : "Hors source connue"}
                              </div>
                            </td>
                            <td>
                              <Badge
                                tone={
                                  protectedRow(r)
                                    ? "neutral"
                                    : r.risk.recommended_action ===
                                        "suggest_uninstall"
                                      ? "bad"
                                      : r.risk.recommended_action === "review"
                                        ? "warn"
                                        : "good"
                                }
                              >
                                {actionLabels[r.risk.recommended_action] ||
                                  r.risk.recommended_action}
                              </Badge>
                            </td>
                            <td className="text-xs text-muted-foreground">
                              {validationLabels[r.validation]}
                            </td>
                            <td>
                              <Button
                                variant="ghost"
                                size="icon"
                                aria-label={`Détails de ${r.app.app_label}`}
                                onClick={() => setDetail(r.app.package_name)}
                              >
                                <ChevronRight />
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-50 px-5 py-4">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <ShieldCheck size={16} />
                    <span>
                      Aucune suppression automatique. Confirmation humaine
                      obligatoire.
                    </span>
                  </div>
                  <Button
                    variant="destructive"
                    disabled={
                      locked ||
                      !liveScan(scan) ||
                      !selected.length ||
                      device.serial !== scan?.device.serial ||
                      !connected
                    }
                    onClick={() =>
                      void run("Désinstallation", async () => {
                        setScan(
                          await invoke<Scan>("uninstall_selected", {
                            packages: selected,
                          }),
                        );
                        setSelected([]);
                        setNotice(
                          "Opération terminée. Consultez les résultats de désinstallation ci-dessous.",
                        );
                      })
                    }
                  >
                    <Trash2 />
                    Désinstaller la sélection{" "}
                    {selected.length ? `(${selected.length})` : ""}
                  </Button>
                </div>
              </section>
              {scan?.uninstalled.length ? (
                <section className="card mt-5 p-5">
                  <h2 className="section-title mb-3">
                    Résultats des désinstallations
                  </h2>
                  {scan.uninstalled.map((u, i) => (
                    <div key={i} className="mb-2 flex gap-3 text-sm">
                      <Badge tone={u.success ? "good" : "bad"}>
                        {u.success ? "Retirée" : "Échec"}
                      </Badge>
                      <span>
                        {u.package} · {u.result}
                      </span>
                    </div>
                  ))}
                </section>
              ) : null}
            </>
          )}

          {page === "exports" && (
            <>
              <div className="mb-6 grid gap-4 lg:grid-cols-3">
                {[
                  {
                    kind: "html",
                    name: "Rapport client",
                    description:
                      "Rapport HTML imprimable : diagnostic, décisions, comparaison et suppressions.",
                    icon: FileText,
                  },
                  {
                    kind: "csv",
                    name: "Inventaire CSV",
                    description:
                      "Applications, permissions, scores, validations et notes pour analyse.",
                    icon: Table2,
                  },
                  {
                    kind: "plan",
                    name: "Plan d’action",
                    description:
                      "Priorités, motifs et commandes autorisées après validation humaine.",
                    icon: Clipboard,
                  },
                ].map(({ kind, name, description, icon: Icon }) => (
                  <section className="card p-6" key={kind}>
                    <div className="mb-5 inline-flex rounded-xl bg-muted p-3 text-primary">
                      <Icon size={23} />
                    </div>
                    <h2 className="section-title mb-2">{name}</h2>
                    <p className="mb-6 min-h-15 text-xs leading-6 text-muted-foreground">
                      {description}
                    </p>
                    <Button
                      variant="outline"
                      disabled={locked || !scan}
                      onClick={() => exportScan(kind)}
                    >
                      <ArrowDownToLine />
                      Exporter {kind.toUpperCase()}
                    </Button>
                  </section>
                ))}
              </div>
              <div className="mb-6 flex flex-wrap gap-3">
                <Button
                  variant="outline"
                  disabled={locked || !scan}
                  onClick={() =>
                    void run("Copie du plan", async () => {
                      await copy(
                        await invoke<string>("action_plan", { selected }),
                      );
                      setNotice("Plan d’action copié.");
                    })
                  }
                >
                  <Clipboard />
                  Copier le plan
                </Button>
                <Button
                  variant="outline"
                  disabled={locked}
                  onClick={() =>
                    void run("Ouverture des rapports", async () => {
                      await invoke("open_folder", { folder: "reports" });
                    })
                  }
                >
                  <FolderOpen />
                  Dossier des rapports
                </Button>
                {report && (
                  <Button
                    variant="secondary"
                    disabled={locked}
                    onClick={() =>
                      void run("Ouverture du rapport", async () => {
                        await invoke("open_report", { path: report });
                      })
                    }
                  >
                    <FileText />
                    Ouvrir le dernier export
                  </Button>
                )}
              </div>
              {scan?.comparison && (
                <section className="card mb-6 p-6">
                  <h2 className="section-title mb-3">Comparaison des scans</h2>
                  {scan.comparison.previous_scan_id ? (
                    <>
                      <p className="mb-4 text-xs text-muted-foreground">
                        Scan #{scan.comparison.current_scan_id} comparé au scan
                        #{scan.comparison.previous_scan_id} du même téléphone.
                      </p>
                      <div className="mb-4 flex gap-3">
                        <Badge tone="good">
                          {scan.comparison.new_apps.length} nouvelles
                        </Badge>
                        <Badge>
                          {scan.comparison.removed_apps.length} retirées
                        </Badge>
                        <Badge>
                          {scan.comparison.unchanged_count} inchangées
                        </Badge>
                        <Badge tone="warn">
                          {scan.comparison.risk_changes.length} risques modifiés
                        </Badge>
                      </div>
                      {[
                        ["Nouvelles", scan.comparison.new_apps],
                        ["Retirées", scan.comparison.removed_apps],
                      ].map(([title, apps]) => (
                        <div key={String(title)} className="mb-3 text-xs">
                          <strong>{String(title)} : </strong>
                          {(apps as typeof scan.comparison.new_apps)
                            .map((a) => a.app_label || a.package)
                            .join(", ") || "Aucune"}
                        </div>
                      ))}
                      {scan.comparison.risk_changes.map((c) => (
                        <div className="mt-2 text-xs" key={c.package}>
                          {c.app_label} : {c.previous_score} → {c.current_score}{" "}
                          · {actionLabels[c.previous_action]} →{" "}
                          {actionLabels[c.current_action]}
                        </div>
                      ))}
                    </>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      Premier scan complet identifié pour ce téléphone. Cette
                      référence permettra la prochaine comparaison.
                    </p>
                  )}
                </section>
              )}
              <section className="card overflow-hidden">
                <div className="flex items-center justify-between border-b p-5">
                  <h2 className="section-title">Historique local</h2>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={locked}
                    onClick={() =>
                      void run("Lecture de l’historique", refreshHistory)
                    }
                  >
                    <RefreshCw />
                    Actualiser
                  </Button>
                </div>
                {!history.length ? (
                  <Empty title="Aucun scan enregistré" icon={History}>
                    Les scans terminés apparaissent ici. Les scans annulés et
                    les démonstrations ne sont pas enregistrés.
                  </Empty>
                ) : (
                  <div className="overflow-auto">
                    <table>
                      <thead>
                        <tr>
                          <th>Date</th>
                          <th>Téléphone</th>
                          <th>Android</th>
                          <th>Applications</th>
                          <th>Score ≥ 60</th>
                          <th />
                        </tr>
                      </thead>
                      <tbody>
                        {history.map((h) => (
                          <tr key={h.id}>
                            <td>{h.date.replace("T", " ")}</td>
                            <td className="font-semibold">
                              {h.device_model || "Modèle inconnu"}
                            </td>
                            <td>{h.android_version}</td>
                            <td>{h.scanned_count}</td>
                            <td>{h.suspicious_count}</td>
                            <td>
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={locked}
                                onClick={() =>
                                  void run("Chargement du scan", async () => {
                                    acceptScan(
                                      await invoke<Scan>("load_history", {
                                        id: h.id,
                                      }),
                                    );
                                    setNotice(
                                      `Scan #${h.id} chargé en consultation.`,
                                    );
                                  })
                                }
                              >
                                Consulter
                                <ChevronRight />
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </>
          )}

          {page === "settings" && (
            <div className="grid gap-6 xl:grid-cols-[1.3fr_1fr]">
              <section className="card p-6">
                <div className="mb-5 flex items-center gap-3">
                  <Sparkles size={21} className="text-primary" />
                  <h2 className="section-title">Analyse IA optionnelle</h2>
                  <Badge>Sur demande uniquement</Badge>
                </div>
                <p className="mb-6 text-xs leading-6 text-muted-foreground">
                  L’analyse ne s’exécute que sur demande. Elle transmet
                  l’inventaire et les métadonnées au fournisseur choisi. Les
                  clés restent côté moteur et ne sont jamais renvoyées à
                  l’interface.
                </p>
                {settings ? (
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      void run("Enregistrement des paramètres", async () => {
                        const s = await invoke<Settings>("save_settings", {
                          settings,
                          apiKey: apiKey || null,
                        });
                        setSettings(s);
                        setApiKey("");
                        setNotice("Paramètres enregistrés.");
                      });
                    }}
                  >
                    <label htmlFor="provider" className="mb-2 block">
                      Fournisseur
                    </label>
                    <select
                      id="provider"
                      className="mb-5 w-full"
                      value={settings.ai_provider}
                      onChange={(e) =>
                        setSettings({
                          ...settings,
                          ai_provider: e.target
                            .value as Settings["ai_provider"],
                        })
                      }
                    >
                      <option value="openai">OpenAI</option>
                      <option value="minimax">MiniMax</option>
                    </select>
                    <label htmlFor="model" className="mb-2 block">
                      Modèle
                    </label>
                    <input
                      id="model"
                      className="mb-5 w-full"
                      required
                      value={settings[`${settings.ai_provider}_model`]}
                      onChange={(e) =>
                        setSettings({
                          ...settings,
                          [`${settings.ai_provider}_model`]: e.target.value,
                        })
                      }
                    />
                    <label htmlFor="url" className="mb-2 block">
                      URL de base
                    </label>
                    <input
                      id="url"
                      className="mb-5 w-full"
                      placeholder="https://api.openai.com/v1"
                      value={settings[`${settings.ai_provider}_base_url`]}
                      onChange={(e) =>
                        setSettings({
                          ...settings,
                          [`${settings.ai_provider}_base_url`]: e.target.value,
                        })
                      }
                    />
                    <label htmlFor="key" className="mb-2 block">
                      Clé API{" "}
                      {settings[`${settings.ai_provider}_key_configured`] && (
                        <span className="ml-2 font-normal text-primary">
                          Clé déjà configurée
                        </span>
                      )}
                    </label>
                    <input
                      id="key"
                      autoComplete="off"
                      type="password"
                      className="mb-2 w-full"
                      placeholder="Laisser vide pour conserver la clé"
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                    />
                    <p className="mb-6 text-[11px] text-muted-foreground">
                      Compatibilité avec les réglages historiques .env du
                      moteur.
                    </p>
                    <Button type="submit" disabled={locked}>
                      <Check />
                      Enregistrer les paramètres
                    </Button>
                  </form>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Paramètres disponibles dans l’application desktop.
                  </p>
                )}
              </section>
              <div className="space-y-6">
                <section className="card p-6">
                  <h2 className="section-title mb-4">Environnement local</h2>
                  <dl className="detail-grid !grid-cols-[70px_1fr]">
                    <dt>ADB</dt>
                    <dd className="text-xs">
                      {boot?.adb_path || "Introuvable"}
                    </dd>
                    <dt>aapt2</dt>
                    <dd className="text-xs">
                      {boot?.aapt2_path || "Absent — noms dérivés du package"}
                    </dd>
                    <dt>Données</dt>
                    <dd className="text-xs">
                      {boot?.root || "Application desktop requise"}
                    </dd>
                  </dl>
                  <div className="mt-5 flex flex-wrap gap-2">
                    {["data", "logs"].map((folder) => (
                      <Button
                        variant="outline"
                        size="sm"
                        key={folder}
                        disabled={locked}
                        onClick={() =>
                          void run("Ouverture du dossier", async () => {
                            await invoke("open_folder", { folder });
                          })
                        }
                      >
                        <FolderOpen />
                        {folder === "data" ? "Données" : "Journaux"}
                      </Button>
                    ))}
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={locked || !scan || scan.demo}
                      onClick={() =>
                        void run("Rechargement de la réputation", async () => {
                          setScan(await invoke<Scan>("reload_reputation"));
                          setNotice("Réputation et scores actualisés.");
                        })
                      }
                    >
                      <RefreshCw />
                      Recharger les listes
                    </Button>
                  </div>
                </section>
                <section className="card p-6">
                  <h2 className="section-title mb-2">
                    Reprendre les données Python
                  </h2>
                  <p className="mb-4 text-xs leading-6 text-muted-foreground">
                    Sélectionnez le dossier de l’ancienne application. La base
                    et les réglages seront vérifiés ; vos données actuelles
                    seront sauvegardées avant remplacement.
                  </p>
                  <Button
                    variant="outline"
                    disabled={locked}
                    onClick={() =>
                      void run("Import de l’ancienne application", async () => {
                        const result = await invoke<{
                          cancelled?: boolean;
                          backup?: string;
                          settings?: Settings;
                        }>("import_legacy");
                        if (!result.cancelled) {
                          setScan(null);
                          setSelected([]);
                          if (result.settings) setSettings(result.settings);
                          setNotice(
                            `Données importées. Sauvegarde : ${result.backup}`,
                          );
                        }
                      })
                    }
                  >
                    <ArrowDownToLine />
                    Importer un dossier
                  </Button>
                </section>
                <section className="rounded-xl border border-dashed border-slate-300 p-6">
                  <h2 className="section-title mb-2">Démonstration</h2>
                  <p className="mb-4 text-xs leading-6 text-muted-foreground">
                    Trois applications fictives pour explorer le triage. Aucun
                    téléphone n’est utilisé et aucune désinstallation n’est
                    autorisée.
                  </p>
                  <Button
                    variant="outline"
                    disabled={locked}
                    onClick={() =>
                      void run("Chargement de la démonstration", async () => {
                        acceptScan(await invoke<Scan>("demo_scan"));
                        setPage("results");
                      })
                    }
                  >
                    <MonitorSmartphone />
                    Ouvrir la démonstration
                  </Button>
                </section>
              </div>
            </div>
          )}
          <footer className="mt-8 flex items-center justify-between border-t pt-5 text-[10px] text-muted-foreground">
            <span>Microwest · Outil de diagnostic atelier</span>
            <span className="flex items-center gap-1.5">
              <ShieldCheck size={12} />
              Décisions humaines · Données locales
            </span>
          </footer>
        </main>
      </div>
      {detailRow && (
        <Details
          row={detailRow}
          scan={scan!}
          busy={locked}
          onClose={() => setDetail(null)}
          update={updateRow}
          openSettings={() =>
            void run("Ouverture des paramètres Android", async () => {
              setNotice(
                await invoke<string>("app_settings", {
                  package: detailRow.app.package_name,
                }),
              );
            })
          }
        />
      )}
      <ConfirmDialog
        open={aiConfirm}
        onOpenChange={setAiConfirm}
        title="Analyser les métadonnées avec l’IA"
        confirm="Lancer l’analyse"
        onConfirm={() =>
          void run("Analyse IA", async () => {
            setScan(await invoke<Scan>("analyze_ai"));
            setNotice(
              "Analyse IA appliquée. Les décisions humaines et protections locales sont conservées.",
            );
          })
        }
      >
        <p>
          Le fournisseur{" "}
          {settings?.ai_provider === "minimax" ? "MiniMax" : "OpenAI"} recevra
          les noms, packages, permissions et métadonnées des applications, ainsi
          que l’inventaire pour comparaison. Le numéro ADB et les notes
          technicien ne sont pas transmis.
        </p>
        <p className="mt-3">
          L’IA donne un avis complémentaire. Elle ne lance jamais de
          désinstallation.
        </p>
      </ConfirmDialog>
    </div>
  );
}

function Details({
  row,
  scan,
  busy,
  onClose,
  update,
  openSettings,
}: {
  row: Row;
  scan: Scan;
  busy: boolean;
  onClose: () => void;
  update: (command: string, args: Record<string, unknown>) => void;
  openSettings: () => void;
}) {
  const [note, setNote] = useState(row.note);
  const [reason, setReason] = useState("");
  const a = row.app;
  useEffect(() => {
    setNote(row.note);
  }, [row.note, a.package_name]);
  return (
    <Dialog.Root
      open
      onOpenChange={(v) => {
        if (!v) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-30 bg-slate-950/30" />
        <Dialog.Content
          aria-describedby={undefined}
          className="fixed bottom-0 right-0 top-0 z-40 w-[min(640px,90vw)] overflow-y-auto bg-white shadow-2xl"
        >
          <div className="sticky top-0 z-10 flex items-center gap-4 border-b bg-white p-6">
            <AppIcon row={row} />
            <div className="min-w-0 flex-1">
              <Dialog.Title className="truncate text-xl font-semibold">
                {a.app_label || a.package_name}
              </Dialog.Title>
              <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
                {a.package_name}
              </p>
            </div>
            <Button
              aria-label="Fermer les détails"
              variant="ghost"
              size="icon"
              onClick={onClose}
            >
              <X />
            </Button>
          </div>
          <div className="space-y-7 p-6">
            <div className="flex flex-wrap gap-2">
              <Badge
                tone={
                  row.risk.score >= 60
                    ? "bad"
                    : row.risk.score >= 30
                      ? "warn"
                      : "good"
                }
              >
                Score {row.risk.score}/100
              </Badge>
              <Badge>{actionLabels[row.risk.recommended_action]}</Badge>
              <Badge>Local : {row.local_risk.score}/100</Badge>
            </div>
            <section>
              <h3 className="mb-3 font-semibold">
                Pourquoi cette proposition ?
              </h3>
              <ul className="space-y-2 text-sm leading-6 text-muted-foreground">
                {row.risk.reasons.map((s, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-primary">•</span>
                    {s}
                  </li>
                ))}
              </ul>
            </section>
            <dl className="detail-grid">
              <dt>Source du nom</dt>
              <dd>
                {a.app_label_source === "apk"
                  ? "Nom réel extrait de l’APK"
                  : "Nom dérivé du package"}
              </dd>
              <dt>Installateur</dt>
              <dd>{a.installer || "Inconnu"}</dd>
              <dt>Version / SDK</dt>
              <dd>
                {a.version_name || "—"} / {a.target_sdk || "—"}
              </dd>
              <dt>Installation</dt>
              <dd>{a.install_date || "Non disponible"}</dd>
              <dt>État Android</dt>
              <dd>{a.enabled || "Non disponible"}</dd>
              <dt>Launcher</dt>
              <dd>
                {a.has_launcher_entry === null
                  ? "Non vérifié"
                  : a.has_launcher_entry
                    ? "Visible"
                    : "Absent"}
              </dd>
              <dt>Rôle HOME</dt>
              <dd>
                {a.is_home_app === null
                  ? "Non vérifié"
                  : a.is_home_app
                    ? "Oui"
                    : "Non"}
              </dd>
              <dt>Accueil actif</dt>
              <dd>
                {a.is_default_home === null
                  ? "Non vérifié"
                  : a.is_default_home
                    ? "Oui — rétablir l’accueil souhaité avant suppression"
                    : "Non"}
              </dd>
            </dl>
            {a.dumpsys_error && (
              <p className="rounded-lg bg-amber-50 p-3 text-xs text-amber-900">
                Métadonnées incomplètes : {a.dumpsys_error}
              </p>
            )}
            {[
              ["Permissions demandées", a.requested_permissions],
              ["Permissions accordées", a.granted_permissions],
              ["Capacités actives confirmées", a.active_capabilities],
              ["Audit visibilité", a.hidden_audit],
              ["Audit notifications", a.notification_audit],
            ].map(([title, items]) => (
              <section key={String(title)}>
                <h3 className="mb-3 text-sm font-semibold">{String(title)}</h3>
                <div className="flex flex-wrap gap-1.5">
                  {(items as string[]).length ? (
                    (items as string[]).map((s) => (
                      <span
                        key={s}
                        className="max-w-full break-all rounded bg-muted px-2 py-1 font-mono text-[10px] text-muted-foreground"
                      >
                        {s}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-muted-foreground">
                      Aucune information confirmée
                    </span>
                  )}
                </div>
              </section>
            ))}
            {row.ai && (
              <section className="rounded-lg bg-teal-50 p-4">
                <h3 className="mb-2 text-sm font-semibold">
                  Avis IA · confiance {row.ai.confidence}
                </h3>
                <p className="text-sm leading-6">{row.ai_text}</p>
              </section>
            )}
            <section className="border-t pt-6">
              <h3 className="mb-3 font-semibold">Validation technicien</h3>
              <div className="flex flex-wrap gap-2">
                {["keep", "review", "remove", "unreviewed"].map((status) => (
                  <Button
                    variant={
                      row.validation === status ? "secondary" : "outline"
                    }
                    key={status}
                    size="sm"
                    disabled={
                      busy ||
                      !scan.scan_id ||
                      row.validation === "removed" ||
                      (status === "remove" && protectedRow(row))
                    }
                    onClick={() =>
                      update("update_validation", {
                        package: a.package_name,
                        status,
                      })
                    }
                  >
                    {validationLabels[status]}
                  </Button>
                ))}
              </div>
              <p className="mt-2 text-[11px] text-muted-foreground">
                La validation s’applique uniquement au scan #
                {scan.scan_id || "—"}.
              </p>
            </section>
            <section>
              <label htmlFor="note" className="mb-2 block">
                Note technicien
              </label>
              <textarea
                id="note"
                rows={3}
                className="w-full"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
              <Button
                className="mt-3"
                variant="outline"
                size="sm"
                disabled={busy}
                onClick={() =>
                  update("update_note", { package: a.package_name, note })
                }
              >
                Enregistrer la note
              </Button>
            </section>
            <section>
              <h3 className="mb-2 text-sm font-semibold">
                Réputation locale du package
              </h3>
              <p className="mb-3 text-xs leading-5 text-muted-foreground">
                Cette réputation est partagée entre les scans. Utilisez la
                validation ci-dessus pour une décision propre au client.
              </p>
              <input
                aria-label="Raison de réputation"
                className="mb-3 w-full"
                placeholder="Raison du classement local"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy || scan.demo}
                  onClick={() =>
                    update("update_reputation", {
                      package: a.package_name,
                      kind: "whitelist",
                      reason,
                    })
                  }
                >
                  Ajouter à la whitelist
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy || scan.demo}
                  onClick={() =>
                    update("update_reputation", {
                      package: a.package_name,
                      kind: "blacklist",
                      reason,
                    })
                  }
                >
                  Ajouter à la blacklist
                </Button>
              </div>
            </section>
            <Button
              variant="outline"
              disabled={busy || scan.demo || !scan.device.serial}
              onClick={openSettings}
            >
              <Settings2 />
              Ouvrir les paramètres sur le téléphone
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
