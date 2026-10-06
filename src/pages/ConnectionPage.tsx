import { invoke } from "@tauri-apps/api/core";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Clipboard,
  RefreshCw,
  Smartphone,
  Unplug,
} from "lucide-react";
import { noDevice, stateLabels } from "../app-config";
import { Badge } from "../components/app-primitives";
import { Button } from "../components/ui/button";
import type { AppController } from "../hooks/useAppController";
type Props = Pick<
  AppController,
  | "connected"
  | "device"
  | "locked"
  | "serial"
  | "setSerial"
  | "run"
  | "detect"
  | "devices"
  | "autoRefresh"
  | "setAutoRefresh"
  | "setPage"
  | "setNotice"
  | "setDiagnostic"
  | "setDevices"
  | "setDevice"
  | "diagnostic"
  | "copy"
  | "setReport"
>;
export function ConnectionPage({
  connected,
  device,
  locked,
  serial,
  setSerial,
  run,
  detect,
  devices,
  autoRefresh,
  setAutoRefresh,
  setPage,
  setNotice,
  setDiagnostic,
  setDevices,
  setDevice,
  diagnostic,
  copy,
  setReport,
}: Props) {
  return (
    <div className="grid items-start gap-3 min-[1000px]:grid-cols-[1.45fr_1fr]">
      <section className="card device-card overflow-hidden">
        <div className="flex items-center justify-between border-b p-3">
          <h2 className="section-title">Téléphone connecté</h2>
          <Badge tone={connected ? "good" : "neutral"}>
            {connected ? "Prêt à analyser" : "En attente"}
          </Badge>
        </div>
        <div className="p-3">
          <div className="mb-3 flex items-center gap-3">
            <div
              className={`device-symbol ${connected ? "is-connected" : ""}`}
            >
              <Smartphone size={30} strokeWidth={1} />
            </div>
            <div>
              <h3 className="mb-1 text-base font-semibold">
                {device.model || "Aucun téléphone connecté"}
              </h3>
              <p className="max-w-md text-sm leading-5 text-muted-foreground">
                {device.message}
              </p>
              {connected && (
                <div className="mt-3 flex gap-2">
                  <Badge>{device.manufacturer}</Badge>
                  <Badge>Android {device.android_version || "inconnu"}</Badge>
                </div>
              )}
            </div>
          </div>
          <label className="mb-2 block" htmlFor="device">
            Appareil ADB
          </label>
          <select
            id="device"
            className="mb-3 w-full"
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
          <label className="mb-3 flex items-center gap-2">
            <input
              type="checkbox"
              checked={autoRefresh}
              disabled={locked}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Actualiser la connexion toutes les 8 secondes
          </label>
          <dl className="detail-grid border-t pt-3">
            <dt>Numéro ADB</dt>
            <dd className="font-mono text-xs">{device.serial || "—"}</dd>
            <dt>Version Android</dt>
            <dd>{device.android_version || "—"}</dd>
            <dt>État</dt>
            <dd>{stateLabels[device.state] || device.state}</dd>
          </dl>
          <div className="mt-3 flex flex-wrap gap-3">
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
      <div className="space-y-3">
        <section className="card p-3">
          <h2 className="section-title mb-3">Préparer la connexion</h2>
          {[
            "Déverrouiller le téléphone et activer les options développeur.",
            "Activer « Débogage USB » et brancher un câble de données.",
            "Accepter la demande d’autorisation RSA sur le téléphone.",
          ].map((s, i) => (
            <div key={s} className="mb-3 flex gap-3 last:mb-0">
              <span className="step-number flex size-6 shrink-0 items-center justify-center rounded-lg text-xs font-semibold">
                {i + 1}
              </span>
              <p className="text-sm leading-5 text-muted-foreground">{s}</p>
            </div>
          ))}
        </section>
        <section className="card p-3">
          <h2 className="section-title mb-2">Outils de connexion</h2>
          <p className="mb-3 text-xs leading-5 text-muted-foreground">
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
                  setNotice("Daemon ADB redémarré et appareils actualisés.");
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
                  setDiagnostic(await invoke<string>("diagnostic", { serial })),
                )
              }
            >
              <Activity />
              Diagnostic
            </Button>
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
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
                    const message = await invoke<string>("daemon_action", {
                      action,
                    });
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
        <section className="card p-3 min-[1000px]:col-span-2">
          <div className="mb-2 flex items-center justify-between">
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
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-lg bg-slate-50 p-4 text-xs leading-5">
            {diagnostic}
          </pre>
        </section>
      )}
    </div>
  );
}
