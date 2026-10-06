import { invoke } from "@tauri-apps/api/core";
import {
  CheckCheck,
  ChevronRight,
  Search,
  ShieldCheck,
  ShieldQuestion,
  Sparkles,
  Table2,
  Trash2,
} from "lucide-react";
import { defaultFilters } from "../app-config";
import { AppIcon, Badge, Empty } from "../components/app-primitives";
import { Button } from "../components/ui/button";
import type { AppController } from "../hooks/useAppController";
import {
  actionLabels,
  liveScan,
  protectedRow,
  removable,
  safeInstallers,
  validationLabels,
  type Filters,
} from "../lib/triage";
import type { Scan } from "../types";
type Props = Pick<
  AppController,
  | "rows"
  | "high"
  | "review"
  | "selected"
  | "scan"
  | "locked"
  | "setAiConfirm"
  | "filters"
  | "changeFilter"
  | "busy"
  | "setSelected"
  | "visible"
  | "setFilters"
  | "setDetail"
  | "toggle"
  | "device"
  | "connected"
  | "run"
  | "setScan"
  | "setNotice"
>;
export function ApplicationsPage({
  rows,
  high,
  review,
  selected,
  scan,
  locked,
  setAiConfirm,
  filters,
  changeFilter,
  busy,
  setSelected,
  visible,
  setFilters,
  setDetail,
  toggle,
  device,
  connected,
  run,
  setScan,
  setNotice,
}: Props) {
  return (
    <>
      <div className="mb-5 grid grid-cols-2 gap-4 xl:grid-cols-4">
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
            className="card flex items-start justify-between p-4"
            key={label}
          >
            <div>
              <div className="mb-2 text-xs text-muted-foreground">{label}</div>
              <div className="text-2xl font-semibold tracking-tight">
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
        <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
          <div>
            <h2 className="section-title">Inventaire des applications</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
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
        <div className="flex flex-wrap gap-2 border-b p-3">
          <div className="relative min-w-60 flex-1">
            <Search
              size={16}
              className="absolute left-3 top-2.5 text-muted-foreground"
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
                      r.risk.recommended_action === "review" && removable(r),
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
            Lancez un scan depuis un téléphone autorisé. Les résultats ne sont
            jamais remplis avec des données fictives.
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
                    data-selected={selected.includes(r.app.package_name)}
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
                          <div className="mt-0.5 max-w-72 truncate font-mono text-xs text-muted-foreground">
                            {r.app.package_name}
                          </div>
                          <div className="mt-0.5 flex gap-1">
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
                        <span className="text-xs text-muted-foreground">
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
                      <div className="mt-0.5 text-xs text-muted-foreground">
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
                            : r.risk.recommended_action === "suggest_uninstall"
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
        <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-50 px-4 py-3">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <ShieldCheck size={16} />
            <span>
              Aucune suppression automatique. Confirmation humaine obligatoire.
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
          <h2 className="section-title mb-3">Résultats des désinstallations</h2>
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
  );
}
