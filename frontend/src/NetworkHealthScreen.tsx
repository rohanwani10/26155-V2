import { useEffect, useState } from "react";
import { getNetworkHealthStatus, setNetworkHealthMode, simulateNetworkEvent } from "./api";

export function NetworkHealthScreen() {
  const [data, setData] = useState<{
    mode: string;
    active_interface: string;
    links: any[];
    alerts: any[];
    recommendations: any[];
    simulated_spike: string | null;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState(false);

  async function loadData() {
    try {
      const res = await getNetworkHealthStatus();
      setData(res);
    } catch {
      // Graceful fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 2000); // 2s live refresh
    return () => clearInterval(interval);
  }, []);

  async function handleSwitchMode(newMode: string) {
    setToggling(true);
    try {
      const res = await setNetworkHealthMode(newMode);
      setData(res);
    } catch {
      // Ignore
    } finally {
      setToggling(false);
    }
  }

  async function handleToggleSpike() {
    setToggling(true);
    try {
      const nextSpike = data?.simulated_spike === "wan-1" ? null : "wan-1";
      const res = await simulateNetworkEvent(nextSpike);
      setData(res);
    } catch {
      // Ignore
    } finally {
      setToggling(false);
    }
  }

  if (loading || !data) {
    return <div className="card"><p>Loading live Network Health telemetry stream...</p></div>;
  }

  const isReal = data.mode === "real";

  return (
    <div>
      <div className="flex-between" style={{ marginBottom: 24, flexWrap: "wrap" }}>
        <div>
          <h1>Network Health & Live Telemetry</h1>
          <p style={{ fontSize: "1.05rem" }}>
            {isReal
              ? `Live Wi-Fi Telemetry Stream from Laptop Interface: ${data.active_interface}`
              : "Live SNMP/NetFlow Telemetry Collector & Local AI Switch Recommendation Engine"}
          </p>
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button
            onClick={() => handleSwitchMode(isReal ? "demo" : "real")}
            disabled={toggling}
            className="btn-dark"
          >
            {isReal ? "🌐 Switch to Multi-WAN Demo Mode" : "📡 Switch to Real Wi-Fi Mode"}
          </button>

          {!isReal && (
            <button
              onClick={handleToggleSpike}
              disabled={toggling}
              className={data.simulated_spike ? "btn-dark" : "btn-red"}
            >
              {data.simulated_spike
                ? "Reset Live Telemetry"
                : "⚡ Simulate WAN-1 Traffic Spike"}
            </button>
          )}
        </div>
      </div>

      {isReal && (
        <div className="card card-red" style={{ marginBottom: 24 }}>
          <div className="flex-between">
            <span className="badge badge-dark">Live Laptop Wi-Fi Stream</span>
            <span className="badge badge-pass">Connected Adapter: {data.active_interface}</span>
          </div>
          <h2 style={{ color: "#FFF", marginTop: 8 }}>Active Laptop Network Telemetry</h2>
          <p style={{ color: "#FFF", fontSize: "0.95rem" }}>
            Currently streaming real throughput (Mbps), live RTT ping latency (ms), and packet loss directly from your laptop's Wi-Fi adapter.
          </p>
        </div>
      )}

      {/* Multi-WAN or Live Wi-Fi Cards */}
      <div className={isReal ? "" : "grid-3"} style={{ marginBottom: 24 }}>
        {data.links.map((link) => {
          const isDegraded = link.status === "DEGRADED";
          return (
            <div
              key={link.link_id}
              className={`card ${isDegraded ? "card-dark" : ""}`}
              style={{
                border: isDegraded ? "2px solid var(--primary-red)" : "1px solid var(--border-light)",
                position: "relative",
              }}
            >
              <div className="flex-between" style={{ marginBottom: 12 }}>
                <span className={`badge ${isDegraded ? "badge-fail" : "badge-pass"}`}>
                  {link.status}
                </span>
                <span
                  className="badge"
                  style={{
                    fontSize: "0.9rem",
                    background: link.health_score > 85 ? "#E6F4EA" : "#FCE8E6",
                    color: link.health_score > 85 ? "#137333" : "#C5221F",
                  }}
                >
                  Health: {link.health_score} / 100
                </span>
              </div>

              <h3 style={{ marginTop: 0, marginBottom: 4, color: isDegraded ? "#FFF" : "var(--text-dark)" }}>
                {link.name}
              </h3>
              <p style={{ fontSize: "0.85rem", margin: 0, color: isDegraded ? "var(--text-light-muted)" : "var(--text-muted)" }}>
                Interface: <code>{link.interface}</code>
              </p>

              <div style={{ marginTop: 18, display: "flex", flexDirection: "column", gap: 10 }}>
                <div>
                  <div className="flex-between" style={{ fontSize: "0.84rem", fontWeight: 600, color: isDegraded ? "#FFF" : "var(--text-dark)" }}>
                    <span>Live Throughput / Load</span>
                    <span>
                      {link.throughput_mbps !== undefined
                        ? `${link.throughput_mbps.toFixed(2)} Mbps (${link.bandwidth_usage_pct.toFixed(1)}%)`
                        : `${link.bandwidth_usage_pct.toFixed(1)}%`}
                    </span>
                  </div>
                  <div
                    style={{
                      height: 8,
                      borderRadius: 4,
                      background: "rgba(0,0,0,0.1)",
                      overflow: "hidden",
                      marginTop: 4,
                    }}
                  >
                    <div
                      style={{
                        height: "100%",
                        width: `${link.bandwidth_usage_pct}%`,
                        background: link.bandwidth_usage_pct > 80 ? "var(--primary-red)" : "#16A34A",
                        transition: "width 0.4s ease",
                      }}
                    />
                  </div>
                </div>

                <div className="grid-2" style={{ gap: 10, marginTop: 4 }}>
                  <div style={{ background: isDegraded ? "var(--dark-surface-hover)" : "var(--light-surface-subtle)", padding: "8px 12px", borderRadius: "10px" }}>
                    <div style={{ fontSize: "0.75rem", color: isDegraded ? "var(--text-light-muted)" : "var(--text-muted)" }}>RTT Ping Latency</div>
                    <div style={{ fontSize: "1rem", fontWeight: 700, color: isDegraded ? "#FFF" : "var(--text-dark)" }}>
                      {link.latency_ms.toFixed(1)} ms
                    </div>
                  </div>
                  <div style={{ background: isDegraded ? "var(--dark-surface-hover)" : "var(--light-surface-subtle)", padding: "8px 12px", borderRadius: "10px" }}>
                    <div style={{ fontSize: "0.75rem", color: isDegraded ? "var(--text-light-muted)" : "var(--text-muted)" }}>Packet Loss</div>
                    <div style={{ fontSize: "1rem", fontWeight: 700, color: isDegraded ? "#FFF" : "var(--text-dark)" }}>
                      {link.packet_loss_pct.toFixed(1)}%
                    </div>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Congestion & Anomaly Alert Feed */}
      {data.alerts.length > 0 && (
        <section className="card" style={{ marginBottom: 24 }}>
          <span className="badge badge-fail" style={{ marginBottom: 12 }}>
            Active Network Alerts ({data.alerts.length})
          </span>
          <h2>Live Anomaly Feed</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 12 }}>
            {data.alerts.map((alert) => (
              <div
                key={alert.alert_id}
                style={{
                  padding: "14px 18px",
                  borderRadius: "14px",
                  background: "#FCE8E6",
                  border: "1px solid rgba(197, 34, 31, 0.2)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <div>
                  <div style={{ fontWeight: 700, color: "#C5221F", fontSize: "0.98rem" }}>
                    {alert.title}
                  </div>
                  <div style={{ fontSize: "0.88rem", color: "#555", marginTop: 2 }}>
                    {alert.description}
                  </div>
                </div>
                <span className="badge badge-high">High Alert</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Local AI Switch Recommendation Engine */}
      <section className="card card-dark">
        <span className="badge badge-red" style={{ marginBottom: 12 }}>
          Local LLM Advisory Engine
        </span>
        <h2 style={{ color: "#FFF", marginTop: 0 }}>Smart Switch & Failover Recommendations</h2>
        <p style={{ color: "var(--text-light-muted)" }}>
          Air-gapped local AI recommendations based on real-time link health comparison.
        </p>

        {data.recommendations.length === 0 ? (
          <div style={{ padding: "16px 0", color: "var(--text-light-muted)" }}>
            🟢 Network link operating within optimal SLA limits. No traffic rerouting required.
          </div>
        ) : (
          data.recommendations.map((rec) => (
            <div
              key={rec.recommendation_id}
              style={{
                background: "var(--dark-surface)",
                padding: 24,
                borderRadius: "16px",
                border: "1px solid var(--border-dark)",
                marginTop: 16,
              }}
            >
              <div className="flex-between" style={{ marginBottom: 10 }}>
                <h3 style={{ color: "#FFF", margin: 0, fontSize: "1.2rem" }}>
                  {rec.action_title}
                </h3>
                <span className="badge badge-yellow">Trigger: {rec.trigger_reason}</span>
              </div>
              <p style={{ color: "var(--text-light-muted)", fontSize: "0.95rem", lineHeight: "1.6" }}>
                {rec.advisory_details}
              </p>

              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: "0.84rem", fontWeight: 700, color: "#FFF", marginBottom: 6 }}>
                  Generated Router CLI Failover Commands:
                </div>
                <pre>{rec.remediation_cli}</pre>
              </div>
            </div>
          ))
        )}
      </section>
    </div>
  );
}
