export type NavTarget = "landing" | "upload" | "bulk-upload" | "fleet" | "training" | "network-health";

import { Sidebar } from "./Sidebar";

export function Nav({
  current,
  onNavigate,
  onLogout,
}: {
  current: NavTarget | null;
  onNavigate: (target: NavTarget) => void;
  onLogout: () => void;
}) {
  return <Sidebar current={current} onNavigate={onNavigate} onLogout={onLogout} />;
}
