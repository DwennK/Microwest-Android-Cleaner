import { ClipboardList } from "lucide-react";
import type { Intervention } from "../types";
import { Badge, Empty } from "./app-primitives";

const labels: Record<Intervention["status"], string> = {
  verified: "Vérifié par l’application",
  manual: "Confirmé par le technicien",
  opened: "Écran ouvert · à terminer",
  failed: "Échec / non confirmé",
  pending: "En cours ou interrompu · non confirmé",
};
export function InterventionJournal({
  entries = [],
}: {
  entries?: Intervention[];
}) {
  return (
    <section className="card mt-3 overflow-hidden">
      <div className="border-b p-3">
        <h2 className="section-title">Journal d’intervention</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Enregistré avec le scan et inclus dans le rapport HTML et le plan
          d’action.
        </p>
      </div>
      {!entries.length ? (
        <Empty title="Aucune intervention enregistrée" icon={ClipboardList}>
          Les modifications, ouvertures d’écrans et confirmations du technicien
          apparaîtront ici.
        </Empty>
      ) : (
        <ol className="divide-y">
          {[...entries].reverse().map((entry, i) => (
            <li key={`${entry.date}-${i}`} className="p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <strong className="text-sm">{entry.action}</strong>
                <Badge
                  tone={
                    entry.status === "verified"
                      ? "good"
                      : entry.status === "failed" || entry.status === "pending"
                        ? "warn"
                        : "neutral"
                  }
                >
                  {labels[entry.status] || "Résultat non confirmé"}
                </Badge>
              </div>
              <p className="mt-1 whitespace-pre-wrap break-words text-xs leading-5">
                {entry.detail}
              </p>
              <time
                dateTime={entry.date}
                className="mt-1 block text-xs text-muted-foreground"
              >
                {new Date(entry.date).toLocaleString("fr-CH")}
              </time>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
