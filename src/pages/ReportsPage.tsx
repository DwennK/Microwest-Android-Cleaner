import { invoke } from "@tauri-apps/api/core";
import {
  ArrowDownToLine,
  ChevronRight,
  Clipboard,
  FileText,
  FolderOpen,
  History,
  RefreshCw,
  Table2,
} from "lucide-react";
import { Badge, Empty } from "../components/app-primitives";
import { Button } from "../components/ui/button";
import type { AppController } from "../hooks/useAppController";
import { actionLabels } from "../lib/triage";
import type { Scan } from "../types";
type Props = Pick<
  AppController,
  | "locked"
  | "scan"
  | "exportScan"
  | "run"
  | "copy"
  | "setNotice"
  | "report"
  | "refreshHistory"
  | "history"
  | "acceptScan"
  | "selected"
>;
export function ReportsPage({
  locked,
  scan,
  exportScan,
  run,
  copy,
  setNotice,
  report,
  refreshHistory,
  history,
  acceptScan,
  selected,
}: Props) {
  return (
    <>
      <div className="mb-3 grid gap-2 lg:grid-cols-3">
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
          <section className="card export-card p-3" key={kind}>
            <div className="inline-flex rounded-lg bg-muted p-1.5 text-primary">
              <Icon size={16} />
            </div>
            <h2 className="section-title">{name}</h2>
            <p className="text-xs leading-5 text-muted-foreground">
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
      <div className="mb-3 flex flex-wrap gap-3">
        <Button
          variant="outline"
          disabled={locked || !scan}
          onClick={() =>
            void run("Copie du plan", async () => {
              await copy(await invoke<string>("action_plan", { selected }));
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
        <section className="card mb-3 p-3">
          <h2 className="section-title mb-3">Comparaison des scans</h2>
          {scan.comparison.previous_scan_id ? (
            <>
              <p className="mb-2 text-xs text-muted-foreground">
                Scan #{scan.comparison.current_scan_id} comparé au scan #
                {scan.comparison.previous_scan_id} du même téléphone.
              </p>
              <div className="mb-2 flex gap-3">
                <Badge tone="good">
                  {scan.comparison.new_apps.length} nouvelles
                </Badge>
                <Badge>{scan.comparison.removed_apps.length} retirées</Badge>
                <Badge>{scan.comparison.unchanged_count} inchangées</Badge>
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
                  {c.app_label} : {c.previous_score} → {c.current_score} ·{" "}
                  {actionLabels[c.previous_action]} →{" "}
                  {actionLabels[c.current_action]}
                </div>
              ))}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">
              Premier scan complet identifié pour ce téléphone. Cette référence
              permettra la prochaine comparaison.
            </p>
          )}
        </section>
      )}
      <section className="card overflow-hidden">
        <div className="flex items-center justify-between border-b p-3">
          <h2 className="section-title">Historique local</h2>
          <Button
            variant="ghost"
            size="sm"
            disabled={locked}
            onClick={() => void run("Lecture de l’historique", refreshHistory)}
          >
            <RefreshCw />
            Actualiser
          </Button>
        </div>
        {!history.length ? (
          <Empty title="Aucun scan enregistré" icon={History}>
            Les scans terminés apparaissent ici. Les scans annulés et les
            démonstrations ne sont pas enregistrés.
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
                            const loaded = await invoke<Scan>("load_history", {
                              id: h.id,
                            });
                            acceptScan(loaded);
                            setNotice(
                              loaded.analysis_notice ||
                                `Scan #${h.id} chargé en consultation.`,
                            );
                            await refreshHistory();
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
  );
}
