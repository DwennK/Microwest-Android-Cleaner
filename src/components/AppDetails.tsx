import * as Dialog from "@radix-ui/react-dialog";
import { Settings2, X } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "./ui/button";
import { actionLabels, protectedRow, validationLabels } from "../lib/triage";
import type { Row, Scan } from "../types";
import { AppIcon, Badge } from "./app-primitives";
export function AppDetails({
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
                        className="max-w-full break-all rounded bg-muted px-2 py-1 font-mono text-xs text-muted-foreground"
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
              <p className="mt-2 text-xs text-muted-foreground">
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
