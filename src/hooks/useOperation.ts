import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useRef, useState } from "react";
import type { Progress } from "../types";

/** One foreground operation at a time, shared by every screen. */
export function useOperation() {
  const [busy, setBusy] = useState("");
  const busyRef = useRef(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    if (!isTauri()) return;
    let active = true;
    const subscription = listen<Progress>("operation-progress", (event) => {
      if (active && busyRef.current) setProgress(event.payload);
    });
    void subscription.catch((e) => {
      if (active) setError(String(e));
    });
    return () => {
      active = false;
      void subscription.then((unlisten) => unlisten()).catch(() => {});
    };
  }, []);

  const run = useCallback(async (title: string, task: () => Promise<void>) => {
    // The ref locks immediately, including double clicks before React renders.
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(title);
    setError("");
    setNotice("");
    setProgress(null);
    try {
      await task();
    } catch (e) {
      setError(String(e));
    } finally {
      busyRef.current = false;
      setBusy("");
      setProgress(null);
    }
  }, []);

  const cancel = useCallback(async () => {
    try {
      await invoke("cancel_operation");
    } catch (e) {
      setError(String(e));
    }
  }, []);

  return {
    busy,
    busyRef,
    progress,
    error,
    setError,
    notice,
    setNotice,
    run,
    cancel,
  };
}
