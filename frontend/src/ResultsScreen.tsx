import { useState } from "react";
import { ApiError, fetchReportPdf } from "./api";
import type { UploadResult } from "./types";

const ISO_FRAMEWORK = "ISO/IEC 27001";

export function ResultsScreen({
  result,
  onUploadAnother,
  onAuthExpired,
  onChat,
}: {
  result: UploadResult;
  onUploadAnother: () => void;
  onAuthExpired: () => void;
  onChat?: (deviceId: string) => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const frameworkOptions = [...Object.keys(result.findings), ISO_FRAMEWORK];
  const [framework, setFramework] = useState(frameworkOptions[0]);

  async function handleDownload() {
    setError(null);
    try {
      const blob = await fetchReportPdf(result.device_id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${result.device_id}-compliance-report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthExpired();
        return;
      }
      setError("Failed to download report");
    }
  }

  const getSeverityBadgeClass = (severity: string) => {
    const s = severity.toLowerCase();
    if (s === "high") return "badge-high";
    if (s === "medium") return "badge-medium";
    if (s === "low") return "badge-low";
    return "badge-dark";
  };

  const findings = result.findings[framework];

  return (
    <div>
      <div className="flex-between" style={{ marginBottom: 24, flexWrap: "wrap" }}>
        <h1>Compliance results</h1>
        <div style={{ minWidth: 220 }}>
          <label htmlFor="framework-select">Framework</label>
          <select
            id="framework-select"
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
          >
            {frameworkOptions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>
      </div>

      <section className="card card-dark" style={{ marginBottom: 24 }}>
        <h2 style={{ color: "#FFF", marginTop: 0 }}>Device Identity</h2>
        <div className="grid-2">
          {result.identity.resource_id ||
          result.identity.account ||
          result.identity.region ? (
            <>
              <p>Resource ID: {result.identity.resource_id ?? "Unknown"}</p>
              <p>Account: {result.identity.account ?? "Unknown"}</p>
              <p>Region: {result.identity.region ?? "Unknown"}</p>
            </>
          ) : (
            <>
              <p>Model: {result.identity.model ?? "Unknown"}</p>
              <p>Serial number: {result.identity.serial_number ?? "Unknown"}</p>
              <p>OS version: {result.identity.os_version ?? "Unknown"}</p>
            </>
          )}
        </div>
      </section>

      {framework === ISO_FRAMEWORK ? (
        <section className="card">
          <p>
            ISO/IEC 27001 Annex A controls are broad control objectives, not
            line-item technical checks -- each is supported by one or more
            facts, shown below as evidence toward that objective. This is not
            a pass/fail verdict on the control itself.
          </p>
          {result.iso_evidence.map((annex) => (
            <div key={annex.control_id} style={{ marginBottom: 24 }}>
              <h3>
                {annex.control_id} — {annex.title}
              </h3>
              <table>
                <thead>
                  <tr>
                    <th>Supporting fact</th>
                    <th>Evidence</th>
                    <th>Remediation (if gap)</th>
                  </tr>
                </thead>
                <tbody>
                  {annex.evidence.map((item) => (
                    <tr key={item.fact_id}>
                      <td>{item.title}</td>
                      <td>
                        <span className={`badge ${item.satisfied ? "badge-pass" : "badge-fail"}`}>
                          {item.satisfied ? "Present" : "Gap"}
                        </span>
                      </td>
                      <td>{item.remediation ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </section>
      ) : (
        <section className="card">
          <div className="flex-between" style={{ marginBottom: 16 }}>
            <h2>{framework} Audit Verdict</h2>
            <span className="badge badge-red" style={{ fontSize: "0.95rem", padding: "6px 14px" }}>
              {findings.filter((f) => f.status === "pass").length} / {findings.length}{" "}
              controls passed
            </span>
          </div>
          <p>
            {findings.filter((f) => f.status === "pass").length} / {findings.length}{" "}
            controls passed
          </p>
          <table>
            <thead>
              <tr>
                <th>Control</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Remediation</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
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
                    <span className={`badge ${f.status.toLowerCase() === "pass" ? "badge-pass" : "badge-fail"}`}>
                      {f.status}
                    </span>
                  </td>
                  <td>{f.remediation ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {error && <p role="alert">{error}</p>}
      <div className="actions-row">
        <button onClick={handleDownload} className="btn-primary">
          Download PDF report
        </button>
        {onChat && (
          <button onClick={() => onChat(result.device_id)} className="btn-dark">
            Ask questions about this device
          </button>
        )}
        <button onClick={onUploadAnother}>Upload another device</button>
      </div>
    </div>
  );
}
