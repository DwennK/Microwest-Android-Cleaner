import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { Globe, House, RefreshCw, ShieldCheck, Store } from "lucide-react";
import { Badge } from "../components/app-primitives";
import { InterventionJournal } from "../components/InterventionJournal";
import { Button } from "../components/ui/button";
import type { AppController } from "../hooks/useAppController";
import type { Scan, TweakStatus } from "../types";

const dnsModes: Record<string, string> = {
  hostname: "Personnalisé",
  opportunistic: "Automatique",
  off: "Désactivé",
};
const dnsMode = (mode: string | null) =>
  dnsModes[mode || ""] || "Valeur Android par défaut";

type Props = Pick<
  AppController,
  | "scan"
  | "device"
  | "locked"
  | "run"
  | "setScan"
  | "setError"
  | "setNotice"
  | "scanNow"
  | "navigate"
>;
export function TweaksPage({
  scan,
  device,
  locked,
  run,
  setScan,
  setError,
  setNotice,
  scanNow,
  navigate,
}: Props) {
  const [reading, setReading] = useState<{
    key: string;
    value: TweakStatus;
  } | null>(null);
  const [blocker, setBlocker] = useState("AdGuard Content Blocker");
  const [updates, setUpdates] = useState("");
  const eligible =
    !!scan &&
    !scan.demo &&
    !scan.cancelled &&
    scan.scan_id !== null &&
    scan.device.state === "device" &&
    device.state === "device" &&
    scan.device.serial === device.serial;
  const key = `${scan?.scan_id}:${device.serial}:${eligible}`;
  const status = reading?.key === key ? reading.value : null;
  const disabled = locked || !eligible;
  const read = async () => {
    setReading(null);
    const value = await invoke<TweakStatus>("tweaks_status", {
      serial: device.serial,
      scanId: scan?.scan_id,
    });
    setReading({ key, value });
  };
  useEffect(() => {
    setReading(null);
    setUpdates("");
    if (eligible) void run("Lecture des réglages du téléphone", read);
    // Refresh once per phone/scan, not on operation lock changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, run]);
  const apply = (action: string, note = "") =>
    void run("Intervention sur le téléphone", async () => {
      const response = await invoke<{
        scan: Scan;
        error: string | null;
        message: string;
      }>("apply_tweak", {
        serial: device.serial,
        scanId: scan?.scan_id,
        action,
        note,
      });
      setScan(response.scan);
      if (response.error) setError(response.error);
      else {
        setNotice(response.message);
        if (action === "confirm_updates") setUpdates("");
      }
      try {
        await read();
      } catch (e) {
        setError(
          [response.error, `Actualisation indisponible : ${String(e)}`]
            .filter(Boolean)
            .join("\n"),
        );
      }
    });
  const appState = (state: boolean | null | undefined) =>
    state === true
      ? "Activé"
      : state === false
        ? "Désactivé"
        : state === null
          ? "Absent pour ce profil"
          : "État non lu";
  const samsungDefault =
    status?.default_browser === "com.sec.android.app.sbrowser";
  return (
    <>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">
          {eligible
            ? `${device.model || "Téléphone connecté"} · scan #${scan.scan_id} · profil principal Android`
            : "Connectez le téléphone et terminez un scan réel pour intervenir."}
        </p>
        <Button
          variant="outline"
          disabled={disabled}
          onClick={() => void run("Lecture des réglages du téléphone", read)}
        >
          <RefreshCw /> Actualiser l’état
        </Button>
      </div>
      {!eligible && (
        <div className="card mb-3 flex flex-wrap items-center justify-between gap-3 p-3">
          <p className="text-sm">
            Les Tweaks nécessitent un scan complet du téléphone sélectionné. Les
            historiques restent consultables ci-dessous.
          </p>
          <Button
            disabled={locked || device.state !== "device"}
            onClick={scanNow}
          >
            Analyser ce téléphone
          </Button>
        </div>
      )}
      {!!status?.warnings.length && (
        <div
          role="status"
          className="mb-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900"
        >
          {status.warnings.join(" · ")}
        </div>
      )}
      <div className="grid gap-3 xl:grid-cols-2">
        <section className="card p-4 xl:col-start-1 xl:row-start-1">
          <h2 className="section-title flex items-center gap-2">
            <ShieldCheck size={18} /> DNS privé
          </h2>
          <p className="my-3 break-words text-sm">
            {status?.dns
              ? `Mode : ${dnsMode(status.dns.mode)} · Hôte : ${status.dns.hostname || "Aucun"}`
              : "Réglage non disponible"}
          </p>
          <p className="mb-3 text-xs leading-5 text-muted-foreground">
            AdGuard : dns.adguard-dns.com. Le réglage précédent est sauvegardé
            avant modification. La lecture du réglage ne vérifie pas la
            connexion ni le filtrage.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={disabled || !status?.dns}
              onClick={() => apply("dns_adguard")}
            >
              Appliquer AdGuard
            </Button>
            <Button
              variant="outline"
              disabled={disabled || !scan?.dns_backup}
              onClick={() => apply("dns_restore")}
            >
              Restaurer le DNS précédent
            </Button>
          </div>
          {scan?.dns_backup && (
            <p className="mt-2 text-xs text-muted-foreground">
              Sauvegarde disponible : {dnsMode(scan.dns_backup.mode)} /{" "}
              {scan.dns_backup.hostname || "aucun hôte"}
            </p>
          )}
        </section>
        <section className="card p-4 xl:col-start-2 xl:row-start-1 xl:row-span-3">
          <h2 className="section-title flex items-center gap-2">
            <Globe size={18} /> Navigateurs et publicités
          </h2>
          <div className="my-3 flex flex-wrap gap-2">
            <Badge>Chrome : {appState(status?.chrome)}</Badge>
            <Badge>Samsung Browser : {appState(status?.samsung)}</Badge>
          </div>
          <p className="mb-3 break-words text-xs text-muted-foreground">
            Navigateur par défaut : {status?.default_browser || "Non identifié"}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              disabled={disabled || status?.samsung !== false}
              onClick={() => apply("samsung_enable")}
            >
              Activer Samsung Browser
            </Button>
            <Button
              variant="outline"
              disabled={disabled}
              onClick={() => apply("samsung_store")}
            >
              {status?.samsung === null
                ? "Installer Samsung Browser"
                : "Fiche Samsung Browser"}
            </Button>
            <Button
              variant="outline"
              disabled={disabled}
              onClick={() => apply("browser_settings")}
            >
              Choisir le navigateur par défaut
            </Button>
            <Button
              variant="outline"
              disabled={
                disabled ||
                status?.chrome !== true ||
                !samsungDefault ||
                status.samsung !== true
              }
              onClick={() => apply("chrome_disable")}
            >
              Désactiver Chrome
            </Button>
            <Button
              variant="outline"
              disabled={disabled || status?.chrome !== false}
              onClick={() => apply("chrome_enable")}
            >
              Réactiver Chrome
            </Button>
          </div>
          <p className="my-3 text-xs leading-5 text-muted-foreground">
            Avant de désactiver Chrome, activez Samsung Browser et choisissez-le
            par défaut sur le téléphone, puis actualisez l’état.
          </p>
          <div className="border-t pt-3">
            <h3 className="text-sm font-semibold">Bloqueur de publicités</h3>
            <p className="my-2 text-xs leading-5 text-muted-foreground">
              Installez le bloqueur depuis sa fiche Play Store, puis activez-le
              dans Samsung Browser → Menu → Bloqueurs de publicités / Modules
              complémentaires. Confirmez ici seulement après vérification sur le
              téléphone.
            </p>
            <div className="mb-3 flex flex-wrap gap-2">
              <Button
                variant="outline"
                disabled={disabled}
                onClick={() => apply("adblock_store")}
              >
                Installer AdGuard Content Blocker
              </Button>
              <Button
                variant="outline"
                disabled={disabled || status?.samsung !== true}
                onClick={() => apply("samsung_open")}
              >
                Ouvrir Samsung Browser
              </Button>
            </div>
            <label
              className="block text-xs font-medium"
              htmlFor="tweak-blocker"
            >
              Bloqueur activé
            </label>
            <input
              id="tweak-blocker"
              className="my-2 w-full"
              maxLength={500}
              value={blocker}
              disabled={disabled}
              onChange={(e) => setBlocker(e.target.value)}
            />
            <Button
              variant="secondary"
              disabled={disabled || !blocker.trim()}
              onClick={() => apply("confirm_adblock", blocker)}
            >
              Confirmer l’activation manuellement
            </Button>
          </div>
        </section>
        <section className="card p-4 xl:col-start-1 xl:row-start-2">
          <h2 className="section-title flex items-center gap-2">
            <House size={18} /> Écran d’accueil
          </h2>
          <p className="my-3 break-words text-sm">
            Accueil actuel : {status?.home || "Non identifié"}
          </p>
          <p className="mb-3 text-xs leading-5 text-muted-foreground">
            Rétablissez One UI Home sur un Samsung compatible, puis utilisez «
            Applications » pour examiner et retirer l’application qui avait
            remplacé l’accueil.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={
                disabled ||
                !status?.one_ui_available ||
                status.home === "com.sec.android.app.launcher"
              }
              onClick={() => apply("home_restore")}
            >
              Rétablir One UI Home
            </Button>
            <Button
              variant="outline"
              disabled={disabled}
              onClick={() => apply("home_settings")}
            >
              Choisir l’écran d’accueil
            </Button>
            <Button variant="ghost" onClick={() => navigate("results")}>
              Voir les applications
            </Button>
          </div>
        </section>
        <section className="card p-4 xl:col-start-1 xl:row-start-3">
          <h2 className="section-title flex items-center gap-2">
            <Store size={18} /> Mises à jour
          </h2>
          <p className="my-3 text-xs leading-5 text-muted-foreground">
            Dans le Play Store : profil → Gérer les applications et l’appareil →
            Mises à jour disponibles → Tout mettre à jour. Attendez la fin avant
            de renseigner le nombre réellement mis à jour.
          </p>
          <Button
            variant="outline"
            disabled={disabled}
            onClick={() => apply("play_store")}
          >
            Ouvrir le Play Store
          </Button>
          <div className="mt-3 border-t pt-3">
            <label
              htmlFor="tweak-updates"
              className="block text-xs font-medium"
            >
              Nombre d’applications mises à jour
            </label>
            <input
              id="tweak-updates"
              className="my-2 w-full"
              type="number"
              min={1}
              max={10000}
              step={1}
              value={updates}
              disabled={disabled}
              onChange={(e) => setUpdates(e.target.value)}
              placeholder="Ex. : 7"
            />
            <Button
              variant="secondary"
              disabled={
                disabled ||
                !/^\d+$/.test(updates) ||
                Number(updates) < 1 ||
                Number(updates) > 10000
              }
              onClick={() => apply("confirm_updates", updates)}
            >
              Confirmer les mises à jour manuellement
            </Button>
          </div>
        </section>
      </div>
      <InterventionJournal entries={scan?.interventions} />
    </>
  );
}
