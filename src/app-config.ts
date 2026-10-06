import {
  FileText,
  ScanLine,
  Settings2,
  Smartphone,
  Table2,
} from "lucide-react";
import { version } from "../package.json";
import { type Filters } from "./lib/triage";
import type { Device } from "./types";
export const appVersion = version;
export const navigation = [
  { id: "connection", label: "Connexion", icon: Smartphone },
  { id: "scan", label: "Analyse du téléphone", icon: ScanLine },
  { id: "results", label: "Applications", icon: Table2 },
  { id: "exports", label: "Rapports & historique", icon: FileText },
  { id: "settings", label: "Paramètres", icon: Settings2 },
] as const;
export type PageId = (typeof navigation)[number]["id"];
export const stateLabels: Record<string, string> = {
  device: "Connecté",
  unauthorized: "Autorisation requise",
  offline: "Hors ligne",
  disconnected: "Déconnecté",
  demo: "Démonstration",
  historical: "Historique",
};
export const defaultFilters: Filters = {
  search: "",
  action: "",
  min: 0,
  permission: "",
  visibility: "",
  sort: "risk",
};
export const noDevice: Device = {
  serial: "",
  state: "disconnected",
  details: "",
  model: "",
  manufacturer: "",
  android_version: "",
  message: "Connectez un téléphone Android pour commencer.",
};
