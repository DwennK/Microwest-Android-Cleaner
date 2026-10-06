import { invoke } from "@tauri-apps/api/core";
import {
  ArrowDownToLine,
  Check,
  FolderOpen,
  MonitorSmartphone,
  RefreshCw,
  Sparkles,
} from "lucide-react";
import { Badge } from "../components/app-primitives";
import { Button } from "../components/ui/button";
import type { AppController } from "../hooks/useAppController";
import type { Scan, Settings } from "../types";
type Props = Pick<
  AppController,
  | "settings"
  | "run"
  | "apiKey"
  | "setSettings"
  | "setApiKey"
  | "setNotice"
  | "locked"
  | "boot"
  | "scan"
  | "setScan"
  | "setSelected"
  | "acceptScan"
  | "setPage"
>;
export function SettingsPage({
  settings,
  run,
  apiKey,
  setSettings,
  setApiKey,
  setNotice,
  locked,
  boot,
  scan,
  setScan,
  setSelected,
  acceptScan,
  setPage,
}: Props) {
  return (
    <div className="grid items-start gap-3 min-[1000px]:grid-cols-[1.3fr_1fr]">
      <section className="card p-3">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <Sparkles size={21} className="text-primary" />
          <h2 className="section-title">Analyse IA optionnelle</h2>
          <Badge>Sur demande uniquement</Badge>
        </div>
        <p className="mb-3 text-xs leading-5 text-muted-foreground">
          L’analyse ne s’exécute que sur demande. Elle transmet l’inventaire et
          les métadonnées au fournisseur choisi. Les clés restent côté moteur et
          ne sont jamais renvoyées à l’interface.
        </p>
        {settings ? (
          <form
            className="settings-form"
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
              className="mb-3 w-full"
              value={settings.ai_provider}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  ai_provider: e.target.value as Settings["ai_provider"],
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
              className="mb-3 w-full"
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
              className="mb-3 w-full"
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
            <p className="mb-3 text-xs text-muted-foreground">
              {settings.ai_provider === "minimax"
                ? "Token/Coding Plan : utilisez la clé de votre abonnement. API à l’usage : utilisez une clé liée à un solde API disponible."
                : "Compatibilité avec les réglages historiques .env du moteur."}
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
      <div className="space-y-3">
        <section className="card p-3">
          <h2 className="section-title mb-2">Environnement local</h2>
          <dl className="detail-grid !grid-cols-[70px_1fr]">
            <dt>ADB</dt>
            <dd className="text-xs">{boot?.adb_path || "Introuvable"}</dd>
            <dt>aapt2</dt>
            <dd className="text-xs">
              {boot?.aapt2_path || "Absent — noms dérivés du package"}
            </dd>
            <dt>Données</dt>
            <dd className="text-xs">
              {boot?.root || "Application desktop requise"}
            </dd>
          </dl>
          <div className="mt-3 flex flex-wrap gap-2">
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
        <section className="card p-3">
          <h2 className="section-title mb-2">Reprendre les données Python</h2>
          <p className="mb-2 text-xs leading-5 text-muted-foreground">
            Sélectionnez le dossier de l’ancienne application. La base et les
            réglages seront vérifiés ; vos données actuelles seront sauvegardées
            avant remplacement.
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
                  setNotice(`Données importées. Sauvegarde : ${result.backup}`);
                }
              })
            }
          >
            <ArrowDownToLine />
            Importer un dossier
          </Button>
        </section>
        <section className="rounded-xl border border-dashed border-slate-300 p-3">
          <h2 className="section-title mb-2">Démonstration</h2>
          <p className="mb-2 text-xs leading-5 text-muted-foreground">
            Trois applications fictives pour explorer le triage. Aucun téléphone
            n’est utilisé et aucune désinstallation n’est autorisée.
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
  );
}
