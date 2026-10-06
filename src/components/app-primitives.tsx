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
    <div className="flex min-h-64 flex-col items-center justify-center px-8 py-12 text-center">
      <div className="mb-5 rounded-2xl bg-muted p-4 text-muted-foreground">
        <Icon size={28} strokeWidth={1.5} />
      </div>
      <h3 className="mb-2 font-semibold">{title}</h3>
      <div className="max-w-lg text-sm leading-6 text-muted-foreground">
        {children}
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
    <img src={src} alt="" className="size-10 rounded-xl object-contain" />
  ) : (
    <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-lg font-semibold text-slate-500">
      {(row.app.app_label || row.app.package_name).slice(0, 1).toUpperCase()}
    </div>
  );
}
