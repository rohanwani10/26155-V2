import { useState } from "react";
import { ApiError, login } from "./api";

export function LoginScreen({
  onLoggedIn,
  onBackToLanding,
}: {
  onLoggedIn: () => void;
  onBackToLanding?: () => void;
}) {
  const [credential, setCredential] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await login(credential);
      onLoggedIn();
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError("Too many failed attempts, try again shortly");
      } else if (err instanceof ApiError && err.status === 401) {
        setError("Invalid password");
      } else {
        setError("Login failed");
      }
    }
  }

  return (
    <div className="standalone-container">
      <div style={{ maxWidth: 840, margin: "40px auto" }} className="card card-dark">
      <div className="grid-2" style={{ alignItems: "center" }}>
        {/* Left Branding & Highlights */}
        <div style={{ paddingRight: 16 }}>
          <div
            style={{
              width: 52,
              height: 52,
              borderRadius: "50%",
              background: "var(--primary-red)",
              color: "#FFF",
              fontWeight: 800,
              fontSize: 26,
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              marginBottom: 16,
              boxShadow: "var(--shadow-red)",
            }}
          >
            U
          </div>
          <h2 style={{ color: "#FFF", fontSize: "1.8rem", marginTop: 0, marginBottom: 8 }}>
            UniConfig
          </h2>
          <p style={{ color: "var(--text-light-muted)", fontSize: "0.98rem", marginBottom: 20 }}>
            Unified Network Security Compliance Auditor & Multi-Vendor RAG Platform.
          </p>

          <ul style={{ listStyle: "none", padding: 0, margin: "0 0 24px 0", color: "#FFF", fontSize: "0.88rem", display: "flex", flexDirection: "column", gap: 10 }}>
            <li style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="badge badge-red">Air-Gapped</span> 100% On-Premise Local AI
            </li>
            <li style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="badge badge-yellow">Audits</span> CIS, NIST, DISA STIG & ISO 27001
            </li>
            <li style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="badge badge-pass">Fixes</span> Automated Copyable CLI Remediations
            </li>
          </ul>

          {onBackToLanding && (
            <button
              onClick={onBackToLanding}
              className="btn"
              style={{ background: "var(--dark-surface-hover)", color: "#FFF", fontSize: "0.85rem" }}
            >
              ← Back to Product Overview
            </button>
          )}
        </div>

        {/* Right Form Card */}
        <div
          style={{
            background: "var(--light-surface)",
            padding: 32,
            borderRadius: "var(--radius-xl)",
            color: "var(--text-dark)",
          }}
        >
          <h1 style={{ fontSize: "1.8rem", marginTop: 0, marginBottom: 4 }}>Log in</h1>
          <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", marginBottom: 20 }}>
            Enter your master admin password to access the compliance console.
          </p>

          <form onSubmit={handleSubmit} style={{ maxWidth: "100%" }}>
            <label>
              Master password
              <div style={{ position: "relative" }}>
                <input
                  type={showPassword ? "text" : "password"}
                  value={credential}
                  onChange={(e) => setCredential(e.target.value)}
                  placeholder="••••••••••••"
                  style={{ paddingRight: 40 }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: "absolute",
                    right: 8,
                    top: "50%",
                    transform: "translateY(-50%)",
                    background: "transparent",
                    border: "none",
                    padding: "4px 8px",
                    fontSize: "0.8rem",
                    color: "var(--text-muted)",
                    cursor: "pointer",
                  }}
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
            </label>
            {error && <p role="alert">{error}</p>}
            <button type="submit" className="btn-primary" style={{ width: "100%", marginTop: 12 }}>
              Log in to Console
            </button>
          </form>
        </div>
      </div>
    </div>
  </div>
);
}
