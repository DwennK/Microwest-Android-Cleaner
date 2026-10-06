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
    <div className="grid items-start gap-3 min-[1000px]:grid-cols-[1.5fr_1fr]">
      <section className="card device-card p-4">
        <div className="mb-3 flex items-center gap-2">
          <ScanLine size={20} className="shrink-0 text-primary" />
          <h2 className="section-title">
            Examiner les applications installées
          </h2>
        </div>
        <p className="mb-3 max-w-xl text-sm leading-5 text-muted-foreground">
          Le scan recueille l’identité des applications, leur provenance et
          leurs accès Android. Les règles de l’atelier calculent ensuite un
          score et proposent les applications à vérifier.
        </p>
        <div className="mb-3 rounded-xl border bg-slate-50 p-3">
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
        <label className="mb-3 flex items-center gap-3">
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
        <p className="mt-2 text-xs text-muted-foreground">
          La durée dépend du nombre d’applications et de la vitesse USB.
        </p>
      </section>
      <div className="space-y-3">
        <section className="card p-3">
          <h2 className="section-title mb-3">Ce qui est analysé</h2>
          {[
            "Package, version, installateur et date",
            "Permissions demandées et accordées",
            "Accessibilité, overlay et notifications actifs",
            "Visibilité, rôle HOME, nom et icône APK",
            "Réputation locale et règles de tri atelier",
          ].map((s) => (
            <div className="mb-2 flex items-center gap-3 text-sm" key={s}>
              <CheckCheck size={17} className="shrink-0 text-primary" />
              {s}
            </div>
          ))}
        </section>
        <div className="rounded-xl bg-[#e8eef4] p-3">
          <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
            <ShieldCheck size={17} className="text-[#224c70]" />
            Un scan ne supprime rien
          </h3>
          <p className="text-xs leading-5 text-muted-foreground">
            Les scores sont des signaux à examiner. La décision finale
            appartient au technicien. Aucun SMS, contact, photo ou contenu de
            notification n’est consulté.
          </p>
        </div>
      </div>
    </div>
  );
}
