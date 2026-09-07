import { useEffect, useState } from "react";
import { ApiError, getFleetSummary } from "./api";
import type { FleetSummary } from "./types";

const DEFAULT_FRAMEWORKS = ["CIS", "ISO/IEC 27001", "NIST SP 800-53", "DISA STIG"];

export function FleetDashboardScreen({
  onViewDevice,
  onAuthExpired,
}: {
  onViewDevice: (deviceId: string) => void;
  onAuthExpired: () => void;
}) {
  const [summary, setSummary] = useState<FleetSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [framework, setFramework] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const result = await getFleetSummary();
        setSummary(result);
        const keys = Object.keys(result.frameworks);
        setFramework(keys.includes("CIS") ? "CIS" : keys[0] ?? "CIS");
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          onAuthExpired();
          return;
        }
        setError("Failed to load fleet summary");
      }
    })();
  }, []);

  const getSeverityBadgeClass = (severity: string) => {
    const s = severity.toLowerCase();
    if (s === "high") return "badge-high";
    if (s === "medium") return "badge-medium";
    if (s === "low") return "badge-low";
    return "badge-dark";
  };

  if (error) return <p role="alert">{error}</p>;
  if (!summary) return <p style={{ padding: 24 }}>Loading fleet summary...</p>;

  const availableFrameworks = Array.from(
    new Set([...Object.keys(summary.frameworks || {}), ...DEFAULT_FRAMEWORKS])
  );

  const activeData =
    framework && summary.frameworks[framework]
      ? summary.frameworks[framework]
      : { total_pass_count: 0, total_fail_count: 0, most_common_failures: [] };

  const totalEvaluated = activeData.total_pass_count + activeData.total_fail_count;
  const passRate = totalEvaluated > 0 ? Math.round((activeData.total_pass_count / totalEvaluated) * 100) : 0;

  return (
    <div>
      <div className="flex-between" style={{ marginBottom: 20, flexWrap: "wrap", gap: 16 }}>
        <div>
          <h1>Fleet dashboard</h1>
          <p style={{ fontSize: "1.1rem" }}>
            <span className="badge badge-dark" style={{ fontSize: "0.9rem", padding: "6px 14px" }}>
              {summary.device_count} device(s) evaluated
            </span>
          </p>
        </div>

        {summary.device_count > 0 && (
          <div>
            <div style={{ fontSize: "0.82rem", fontWeight: 700, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Compliance Standards & Frameworks
            </div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              {availableFrameworks.map((name) => {
                const active = framework === name;
                const icon = name.includes("ISO") ? "📋 " : name.includes("CIS") ? "🛡️ " : name.includes("NIST") ? "🏛️ " : "⚙️ ";
                return (
                  <button
                    key={name}
                    type="button"
                    onClick={() => setFramework(name)}
                    className={active ? "btn-primary" : "btn-dark"}
                    style={{
                      padding: "9px 20px",
                      borderRadius: "20px",
                      fontSize: "0.92rem",
                      fontWeight: 700,
                      cursor: "pointer",
                      transition: "all 0.2s ease",
                      border: active ? "1px solid var(--primary-red)" : "1px solid var(--border-dark)",
                    }}
                  >
                    {icon} {name}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {summary.device_count === 0 ? (
        <div className="card">
          <p>No devices uploaded yet.</p>
        </div>
      ) : (
        <>
          {framework && (
            <div className="grid-2" style={{ marginBottom: 24 }}>
              <div className="card card-red">
                <span className="badge badge-dark" style={{ marginBottom: 12 }}>
                  Selected Standard
                </span>
                <h2 style={{ marginTop: 0, fontSize: "1.8rem" }}>{framework} Fleet Overview</h2>
                <p style={{ fontWeight: 600, fontSize: "1.05rem" }}>
                  {activeData.total_pass_count} passed / {activeData.total_fail_count} failed across the fleet
                </p>
              </div>

              <div className="card card-dark">
                <span className="badge badge-red" style={{ marginBottom: 12 }}>
                  Compliance Health
                </span>
                <h3 style={{ marginTop: 0, fontSize: "1.4rem", color: "#FFF" }}>
                  {passRate}% Compliance Pass Rate
                </h3>
                <p style={{ color: "var(--text-light-muted)" }}>
                  Monitoring real-time compliance posture across all connected fleet assets.
                </p>
              </div>
            </div>
          )}

          {framework && (
            <section className="card">
              <h2>{framework} fleet totals</h2>
              <p>
                {activeData.total_pass_count} passed / {activeData.total_fail_count} failed across the fleet
              </p>
              <h3>Most common failures</h3>
              {activeData.most_common_failures.length === 0 ? (
                <p>No failures for {framework}.</p>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th>Control</th>
                      <th>Title</th>
                      <th>Severity</th>
                      <th>Devices failing</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeData.most_common_failures.map((f) => (
                      <tr key={f.control_id}>
                        <td>
                          <code>{f.control_id}</code>
                        </td>
                        <td>{f.title}</td>
                        <td>
                          <span className={`badge ${getSeverityBadgeClass(f.severity)}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td>
                          <span className="badge badge-fail">{f.fail_count} failing</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          )}

          <section className="card">
            <h2>Devices</h2>
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  {framework && (
                    <>
                      <th>{framework} pass</th>
                      <th>{framework} fail</th>
                    </>
                  )}
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {summary.devices.map((device) => (
                  <tr key={device.device_id}>
                    <td style={{ fontWeight: 600 }}>
                      {device.identity?.model ??
                        device.identity?.resource_id ??
                        device.device_id}
                    </td>
                    {framework && (
                      <>
                        <td>
                          <span className="badge badge-pass">
                            {device.pass_counts[framework] ?? 0}
                          </span>
                        </td>
                        <td>
                          <span className="badge badge-fail">
                            {device.fail_counts[framework] ?? 0}
                          </span>
                        </td>
                      </>
                    )}
                    <td>
                      <button onClick={() => onViewDevice(device.device_id)} className="btn-dark">
                        View results
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}
    </div>
  );
}
