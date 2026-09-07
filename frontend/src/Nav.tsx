export type NavTarget = "landing" | "upload" | "bulk-upload" | "fleet" | "training" | "network-health";

const LINKS: { target: NavTarget; label: string }[] = [
  { target: "upload", label: "Upload device" },
  { target: "bulk-upload", label: "Bulk upload" },
  { target: "fleet", label: "Fleet dashboard" },
  { target: "network-health", label: "Network Health" },
  { target: "training", label: "Vendor training" },
];

export function Nav({
  current,
  onNavigate,
  onLogout,
}: {
  current: NavTarget | null;
  onNavigate: (target: NavTarget) => void;
  onLogout: () => void;
}) {
  return (
    <nav className="landing-nav">
      <div className="nav-brand" onClick={() => onNavigate("landing")}>
        <span className="nav-brand-logo">U</span>
        <span>UniConfig</span>
      </div>
      <div className="nav-links">
        {LINKS.map(({ target, label }) => (
          <button
            key={target}
            onClick={() => onNavigate(target)}
            disabled={current === target}
          >
            {label}
          </button>
        ))}
        <button onClick={onLogout} className="btn-dark">
          Log out
        </button>
      </div>
    </nav>
  );
}
