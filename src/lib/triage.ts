import type { Row, Scan } from "../types";
export const validationLabels: Record<string, string> = {
  unreviewed: "Non validée",
  keep: "Conserver",
  review: "À vérifier",
  remove: "Retirer",
  removed: "Retirée",
};
export const actionLabels: Record<string, string> = {
  keep: "Conserver",
  review: "À vérifier",
  suggest_uninstall: "Retrait proposé",
  do_not_touch: "Protégée",
};
export const safeInstallers = [
  "com.android.vending",
  "com.sec.android.app.samsungapps",
  "com.sec.android.app.updatecenter",
  "com.samsung.android.app.updatecenter",
  "com.sec.android.easyMover",
];
export function protectedRow(row: Row) {
  return (
    row.app.is_system_app || row.risk.recommended_action === "do_not_touch"
  );
}
export function removable(row: Row) {
  return (
    !protectedRow(row) &&
    !["keep", "removed"].includes(row.validation) &&
    !row.app.dumpsys_error
  );
}
export function liveScan(scan: Scan | null) {
  return (
    !!scan &&
    !!scan.scan_id &&
    !scan.demo &&
    !scan.cancelled &&
    scan.device.state === "device" &&
    !!scan.device.serial
  );
}
export interface Filters {
  search: string;
  action: string;
  min: number;
  permission: string;
  visibility: string;
  sort: "risk" | "name" | "installer";
}
export function filteredRows(rows: Row[], filters: Filters): Row[] {
  const query = filters.search.trim().toLocaleLowerCase();
  return rows
    .filter((r) => {
      const a = r.app;
      if (
        query &&
        !`${a.app_label} ${a.package_name} ${a.installer} ${r.note}`
          .toLocaleLowerCase()
          .includes(query)
      )
        return false;
      if (
        r.risk.score < filters.min ||
        (filters.action && r.risk.recommended_action !== filters.action)
      )
        return false;
      if (
        filters.visibility === "hidden" &&
        a.has_launcher_entry !== false &&
        !a.hidden_audit.some((s) => s.includes("générique"))
      )
        return false;
      if (
        filters.visibility === "sideload" &&
        safeInstallers.includes(a.installer)
      )
        return false;
      if (filters.visibility === "home" && !a.is_home_app) return false;
      if (filters.permission) {
        const flags: Record<string, boolean> = {
          ACCESSIBILITY: a.has_accessibility,
          NOTIFICATION:
            a.has_notification_listener || a.requests_post_notifications,
          OVERLAY: a.has_overlay,
          DEVICE_ADMIN: a.has_device_admin,
          VPN: a.has_vpn_service,
        };
        const haystack = [
          ...a.requested_permissions,
          ...a.granted_permissions,
          ...a.active_capabilities,
        ]
          .join(" ")
          .toUpperCase();
        if (
          !flags[filters.permission] &&
          !haystack.includes(filters.permission)
        )
          return false;
      }
      return true;
    })
    .sort((a, b) =>
      filters.sort === "name"
        ? a.app.app_label.localeCompare(b.app.app_label)
        : filters.sort === "installer"
          ? a.app.installer.localeCompare(b.app.installer)
          : b.risk.score - a.risk.score,
    );
}
