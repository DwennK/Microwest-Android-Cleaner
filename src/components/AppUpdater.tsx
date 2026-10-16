import { invoke, isTauri } from "@tauri-apps/api/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { appVersion } from "../app-config";
import type { AppController } from "../hooks/useAppController";
import { ConfirmDialog } from "./ui/alert-dialog";
import { Button } from "./ui/button";

type UpdateInfo = { version: string; notes: string };
type Props = Pick<AppController, "locked" | "run" | "page">;

export function AppUpdater({ locked, run, page }: Props) {
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState("");
  const [confirm, setConfirm] = useState(false);
  const checkingRef = useRef(false);
  const lockedRef = useRef(locked);
  lockedRef.current = locked;
  const mounted = useRef(false);
  const check = useCallback(async (manual = false) => {
    if (!isTauri() || checkingRef.current || lockedRef.current) return;
    checkingRef.current = true;
    setChecking(true);
    if (manual) setMessage("");
    try {
      const available = await invoke<UpdateInfo | null>("check_update");
      if (!mounted.current) return;
      setUpdate(available);
      setMessage(available ? "" : "Votre application est à jour.");
    } catch (error) {
      if (mounted.current && manual) setMessage(String(error));
    } finally {
      checkingRef.current = false;
      if (mounted.current) setChecking(false);
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    // Retry when startup/another operation is busy; then check every six hours.
    let nextCheck = 0;
    const tick = () => {
      if (import.meta.env.DEV || lockedRef.current || Date.now() < nextCheck)
        return;
      nextCheck = Date.now() + 6 * 60 * 60 * 1000;
      void check();
    };
    const startup = window.setTimeout(tick, 5000);
    const timer = window.setInterval(tick, 60000);
    return () => {
      mounted.current = false;
      window.clearTimeout(startup);
      window.clearInterval(timer);
    };
  }, [check]);

  if (page !== "settings" && !update) return null;
  return (
    <section className="card mb-3 p-3" aria-label="Mises à jour">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">
            {update
              ? `Version ${update.version} disponible`
              : `Application · ${appVersion}`}
          </h2>
          <p className="mt-1 text-xs text-muted-foreground">
            {update
              ? locked
                ? "La mise à jour pourra être installée à la fin de l’opération en cours."
                : "L’installation fermera l’application. Vos données enregistrées seront conservées."
              : "Les nouvelles versions sont recherchées automatiquement sur GitHub."}
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={locked || checking || !isTauri()}
            onClick={() => void check(true)}
          >
            {checking ? "Vérification…" : "Vérifier les mises à jour"}
          </Button>
          {update && (
            <Button
              size="sm"
              disabled={locked || checking}
              onClick={() => setConfirm(true)}
            >
              Installer la mise à jour
            </Button>
          )}
        </div>
      </div>
      {message && (
        <p role="status" className="mt-2 text-xs">
          {message}
        </p>
      )}
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title={`Installer la version ${update?.version ?? ""} ?`}
        confirm="Télécharger et installer"
        onConfirm={() => {
          setConfirm(false);
          if (locked || !update) return;
          const version = update.version;
          void run("Mise à jour de l’application", async () => {
            await invoke("install_update", { version });
          });
        }}
      >
        L’application va télécharger la mise à jour, vérifier sa signature puis
        se fermer pour l’installer. Les scans enregistrés, les notes et les
        paramètres seront conservés. Exportez les résultats non enregistrés
        avant de continuer.
      </ConfirmDialog>
    </section>
  );
}
