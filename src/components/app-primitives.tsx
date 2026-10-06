import { invoke, isTauri } from "@tauri-apps/api/core";
import { ScanLine } from "lucide-react";
import { useEffect, useState } from "react";
import type { Row } from "../types";
export function Badge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
export function Empty({
  title,
  children,
  icon: Icon = ScanLine,
}: {
  title: string;
  children: React.ReactNode;
  icon?: typeof ScanLine;
}) {
  return (
    <div className="flex items-center gap-3 px-4 py-5">
      <div className="shrink-0 rounded-lg bg-muted p-2 text-muted-foreground">
        <Icon size={20} strokeWidth={1.5} />
      </div>
      <div>
        <h3 className="font-semibold">{title}</h3>
        <div className="mt-1 text-xs leading-5 text-muted-foreground">
          {children}
        </div>
      </div>
    </div>
  );
}
export function AppIcon({ row }: { row: Row }) {
  const [src, setSrc] = useState("");
  useEffect(() => {
    let active = true;
    setSrc("");
    if (row.app.icon_path && isTauri())
      invoke<string>("app_icon", { package: row.app.package_name })
        .then((v) => {
          if (active) setSrc(v);
        })
        .catch(() => {});
    return () => {
      active = false;
    };
  }, [row.app.package_name, row.app.icon_path]);
  return src ? (
    <img
      src={src}
      alt=""
      className="size-7 shrink-0 rounded-lg object-contain"
    />
  ) : (
    <div className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-sm font-semibold text-slate-500">
      {(row.app.app_label || row.app.package_name).slice(0, 1).toUpperCase()}
    </div>
  );
}
