import { CheckCheck, ScanLine, ShieldCheck, Smartphone } from "lucide-react";
import { stateLabels } from "../app-config";
import { Badge } from "../components/app-primitives";
import { Button } from "../components/ui/button";
import type { AppController } from "../hooks/useAppController";
type Props = Pick<
  AppController,
  | "device"
  | "connected"
  | "includeSystem"
  | "locked"
  | "setIncludeSystem"
  | "scanNow"
>;
export function ScanPage({
  device,
  connected,
  includeSystem,
  locked,
  setIncludeSystem,
  scanNow,
}: Props) {
  return (
    <div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
      <section className="card p-8">
        <div className="mb-7 inline-flex rounded-2xl bg-teal-50 p-4 text-primary">
          <ScanLine size={32} />
        </div>
        <h2 className="mb-3 text-2xl font-semibold">
          Examiner les applications installées
        </h2>
        <p className="mb-7 max-w-xl text-sm leading-7 text-muted-foreground">
          Le scan recueille l’identité des applications, leur provenance et
          leurs accès Android. Les règles de l’atelier calculent ensuite un
          score et proposent les applications à vérifier.
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
          <span className="font-normal text-muted-foreground">(protégées)</span>
        </label>
        <Button disabled={locked || !connected} onClick={scanNow}>
          <ScanLine />
          Lancer le scan complet
        </Button>
        <p className="mt-4 text-xs text-muted-foreground">
          La durée dépend du nombre d’applications et de la vitesse USB.
        </p>
      </section>
      <div className="space-y-6">
        <section className="card p-6">
          <h2 className="section-title mb-5">Ce qui est analysé</h2>
          {[
            "Package, version, installateur et date",
            "Permissions demandées et accordées",
            "Accessibilité, overlay et notifications actifs",
            "Visibilité, rôle HOME, nom et icône APK",
            "Réputation locale et règles de tri atelier",
          ].map((s) => (
            <div className="mb-4 flex items-center gap-3 text-sm" key={s}>
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
            appartient au technicien. Aucun SMS, contact, photo ou contenu de
            notification n’est consulté.
          </p>
        </div>
      </div>
    </div>
  );
}
