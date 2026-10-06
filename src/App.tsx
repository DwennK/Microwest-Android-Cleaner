import { invoke } from "@tauri-apps/api/core";
import {
  Check,
  ChevronRight,
  Info,
  LoaderCircle,
  ScanLine,
  ShieldCheck,
  Square,
  X,
} from "lucide-react";
import { appVersion, navigation, stateLabels } from "./app-config";
import { Badge } from "./components/app-primitives";
import { AppDetails } from "./components/AppDetails";
import { ConfirmDialog } from "./components/ui/alert-dialog";
import { Button } from "./components/ui/button";
import { useAppController } from "./hooks/useAppController";
import { ApplicationsPage } from "./pages/ApplicationsPage";
import { ConnectionPage } from "./pages/ConnectionPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ScanPage } from "./pages/ScanPage";
import { SettingsPage } from "./pages/SettingsPage";
import type { Scan } from "./types";
export default function App() {
  const app = useAppController();
  const {
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
    detailRow,
    setDetail,
    updateRow,
    run,
    aiConfirm,
    setAiConfirm,
    setScan,
    settings,
  } = app;
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
            <div className="mt-0.5 text-xs tracking-widest text-slate-400">
              ANDROID CLEANER
            </div>
          </div>
        </div>
        <div className="eyebrow px-7 pb-3 text-slate-400">
          Espace technicien
        </div>
        <nav aria-label="Navigation principale" className="space-y-1 px-3">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              aria-current={page === id ? "page" : undefined}
              className={`nav-item ${page === id ? "active" : ""}`}
              onClick={() => navigate(id)}
            >
              <Icon size={18} strokeWidth={1.7} />
              <span>{label}</span>
              {id === "results" && rows.length > 0 && (
                <span className="ml-auto rounded bg-white/10 px-1.5 text-xs">
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
          <p className="mt-2 text-xs leading-5 text-slate-400">
            Métadonnées uniquement.
            <br />
            Chaque suppression exige une confirmation humaine.
          </p>
        </div>
        <div className="px-6 py-6 text-xs text-slate-400">
          MICROWEST · VERSION {appVersion}
          <br />
          <span className="text-slate-400">Shopy Phone Sàrl</span>
        </div>
      </aside>
      <div className="min-w-0">
        <header className="flex h-16 items-center justify-between border-b bg-white px-6">
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
          <div className="page-heading">
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
                    onClick={() => void cancel()}
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
                  <div className="mt-1 text-right text-xs text-muted-foreground">
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

          {page === "connection" && <ConnectionPage {...app} />}

          {page === "scan" && <ScanPage {...app} />}

          {page === "results" && <ApplicationsPage {...app} />}

          {page === "exports" && <ReportsPage {...app} />}

          {page === "settings" && <SettingsPage {...app} />}
          <footer className="mt-6 flex items-center justify-between border-t pt-5 text-xs text-muted-foreground">
            <span>Microwest · Outil de diagnostic atelier</span>
            <span className="flex items-center gap-1.5">
              <ShieldCheck size={12} />
              Décisions humaines · Données locales
            </span>
          </footer>
        </main>
      </div>
      {detailRow && (
        <AppDetails
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
