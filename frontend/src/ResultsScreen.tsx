import { useState } from "react";
import { ApiError, fetchReportPdf } from "./api";
import type { UploadResult } from "./types";

const ISO_FRAMEWORK = "ISO/IEC 27001";

export function ResultsScreen({
  result,
  onUploadAnother,
  onAuthExpired,
}: {
  result: UploadResult;
  onUploadAnother: () => void;
  onAuthExpired: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  // CIS/NIST/DISA STIG are always real, evaluated options (never
  // disabled/"coming soon") -- ISO is a distinct evidentiary view, added
  // alongside them in the same selector rather than a fifth pass/fail table.
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

  const findings = result.findings[framework];

  return (
    <div>
      <h1>Compliance results</h1>
      <section>
        <h2>Device</h2>
        <p>Model: {result.identity.model ?? "Unknown"}</p>
        <p>Serial number: {result.identity.serial_number ?? "Unknown"}</p>
        <p>OS version: {result.identity.os_version ?? "Unknown"}</p>
      </section>

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

      {framework === ISO_FRAMEWORK ? (
        <section>
          <p>
            ISO/IEC 27001 Annex A controls are broad control objectives, not
            line-item technical checks -- each is supported by one or more
            facts, shown below as evidence toward that objective. This is not
            a pass/fail verdict on the control itself.
          </p>
          {result.iso_evidence.map((annex) => (
            <div key={annex.control_id}>
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
                      <td>{item.satisfied ? "Present" : "Gap"}</td>
                      <td>{item.remediation ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </section>
      ) : (
        <section>
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
                  <td>{f.control_id}</td>
                  <td>{f.title}</td>
                  <td>{f.severity}</td>
                  <td>{f.status}</td>
                  <td>{f.remediation ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {error && <p role="alert">{error}</p>}
      <button onClick={handleDownload}>Download PDF report</button>
      <button onClick={onUploadAnother}>Upload another device</button>
    </div>
  );
}
