import { useState } from "react";
import type { NavTarget } from "./Nav";

interface SidebarProps {
  current: NavTarget | null;
  onNavigate: (target: NavTarget) => void;
  onLogout: () => void;
}

interface SidebarLink {
  target: NavTarget;
  label: string;
  badge?: string;
  icon: React.ReactNode;
}

const LINKS: SidebarLink[] = [
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
    badge: "Batch",
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
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
        <line x1="8" y1="21" x2="16" y2="21" />
        <line x1="12" y1="17" x2="12" y2="21" />
      </svg>
    ),
  },
  {
    target: "training",
    label: "Vendor Training",
    badge: "AI",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L2 7l10 5 10-5-10-5z" />
        <path d="M2 17l10 5 10-5" />
        <path d="M2 12l10 5 10-5" />
      </svg>
    ),
  },
  {
    target: "network-health",
    label: "Network Health",
    badge: "Live",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    ),
  },
  {
    target: "global-chat",
    label: "Air-gapped AI Assistant",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
      </svg>
    ),
  },
];

export function Sidebar({ current, onNavigate, onLogout }: SidebarProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  function handleNavClick(target: NavTarget) {
    onNavigate(target);
    setMobileOpen(false);
  }

  return (
    <>
      {/* Mobile Top Header */}
      <div className="mobile-header">
        <div className="sidebar-brand-mini" onClick={() => handleNavClick("landing")}>
          <span className="sidebar-brand-logo">U</span>
          <span className="sidebar-brand-title">UniConfig</span>
        </div>
        <button
          className="mobile-toggle-btn"
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle Navigation Menu"
        >
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            {mobileOpen ? (
              <path d="M18 6L6 18M6 6l12 12" strokeLinecap="round" strokeLinejoin="round" />
            ) : (
              <path d="M4 6h16M4 12h16M4 18h16" strokeLinecap="round" strokeLinejoin="round" />
            )}
          </svg>
        </button>
      </div>

      {/* Backdrop for mobile view */}
      {mobileOpen && (
        <div className="sidebar-backdrop" onClick={() => setMobileOpen(false)} />
      )}

      {/* Sidebar Panel */}
      <aside className={`sidebar ${mobileOpen ? "mobile-open" : ""}`}>
        <div className="sidebar-header">
          <div className="sidebar-brand" onClick={() => handleNavClick("landing")}>
            <div className="sidebar-brand-logo">U</div>
            <div className="sidebar-brand-text">
              <span className="sidebar-brand-title">UniConfig</span>
              <span className="sidebar-brand-subtitle">Compliance Suite</span>
            </div>
          </div>
        </div>

        <div className="sidebar-section-label">Navigation</div>

        <nav className="sidebar-nav">
          {LINKS.map(({ target, label, badge, icon }) => {
            const isActive = current === target;
            return (
              <button
                key={target}
                type="button"
                className={`sidebar-link ${isActive ? "active" : ""}`}
                onClick={() => handleNavClick(target)}
                disabled={isActive}
              >
                <span className="sidebar-link-icon">{icon}</span>
                <span className="sidebar-link-text">{label}</span>
                {badge && <span className="sidebar-badge">{badge}</span>}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user-card">
            <div className="sidebar-user-avatar">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
              </svg>
            </div>
            <div className="sidebar-user-info">
              <span className="sidebar-user-name">Active Session</span>
              <span className="sidebar-user-status">Online</span>
            </div>
          </div>

          <button
            type="button"
            className="sidebar-logout-btn"
            onClick={onLogout}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
            <span>Log out</span>
          </button>
        </div>
      </aside>
    </>
  );
}
