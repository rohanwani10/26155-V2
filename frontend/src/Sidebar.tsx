export type NavTarget =
  | "landing"
  | "upload"
  | "bulk-upload"
  | "fleet"
  | "network-health"
  | "training";

const MAIN_LINKS: { target: NavTarget; label: string; icon: React.ReactNode }[] = [
  {
    target: "upload",
    label: "Upload Device",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
        <polyline points="17 8 12 3 7 8" />
        <line x1="12" y1="3" x2="12" y2="15" />
      </svg>
    ),
  },
  {
    target: "bulk-upload",
    label: "Bulk Upload",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
        <line x1="12" y1="11" x2="12" y2="17" />
        <line x1="9" y1="14" x2="15" y2="14" />
      </svg>
    ),
  },
  {
    target: "fleet",
    label: "Fleet Dashboard",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
      </svg>
    ),
  },
  {
    target: "network-health",
    label: "Network Health",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    ),
  },
  {
    target: "training",
    label: "Vendor Training",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="4 17 10 11 14 15 20 9" />
        <line x1="14" y1="9" x2="20" y2="9" />
        <line x1="20" y1="9" x2="20" y2="15" />
      </svg>
    ),
  },
];

export function Sidebar({
  current,
  onNavigate,
  onLogout,
}: {
  current: NavTarget | null;
  onNavigate: (target: NavTarget) => void;
  onLogout: () => void;
}) {
  return (
    <aside className="sidebar">
      <div>
        {/* Brand Header */}
        <div className="sidebar-brand" onClick={() => onNavigate("landing")}>
          <span className="nav-brand-logo">U</span>
          <div>
            <div style={{ fontWeight: 800, fontSize: "1.1rem", color: "#FFF", letterSpacing: "-0.02em" }}>
              UniConfig
            </div>
            <div style={{ fontSize: "0.72rem", color: "var(--text-light-muted)", fontWeight: 500 }}>
              Compliance Console
            </div>
          </div>
        </div>

        {/* Navigation Section */}
        <div className="sidebar-section-label">MAIN CONSOLE</div>
        <nav className="sidebar-nav">
          {MAIN_LINKS.map(({ target, label, icon }) => (
            <button
              key={target}
              onClick={() => onNavigate(target)}
              disabled={current === target}
              className={`sidebar-button ${current === target ? "active" : ""}`}
            >
              <span className="sidebar-icon">{icon}</span>
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-section-label" style={{ marginTop: 24 }}>OVERVIEW</div>
        <nav className="sidebar-nav">
          <button
            onClick={() => onNavigate("landing")}
            disabled={current === "landing"}
            className={`sidebar-button ${current === "landing" ? "active" : ""}`}
          >
            <span className="sidebar-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
                <polyline points="9 22 9 12 15 12 15 22" />
              </svg>
            </span>
            <span>Product Overview</span>
          </button>
        </nav>
      </div>

      {/* Clean User Footer Card */}
      <div className="sidebar-footer">
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <div
            style={{
              width: 34,
              height: 34,
              borderRadius: "50%",
              background: "var(--dark-surface-hover)",
              border: "1px solid var(--border-dark)",
              color: "#FFF",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 700,
              fontSize: "0.82rem",
              position: "relative",
            }}
          >
            AU
            <span
              style={{
                position: "absolute",
                bottom: 0,
                right: 0,
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: "#16A34A",
                border: "2px solid var(--dark-bg)",
              }}
            />
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ color: "#FFF", fontWeight: 600, fontSize: "0.86rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              Admin Console
            </div>
            <div style={{ color: "var(--text-light-muted)", fontSize: "0.74rem" }}>
              admin@uniconfig.io
            </div>
          </div>
        </div>

        <button onClick={onLogout} className="sidebar-logout-btn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          Log out
        </button>
      </div>
    </aside>
  );
}
