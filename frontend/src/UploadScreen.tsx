import { useState } from "react";
import { ApiError, uploadDevice } from "./api";
import type { UploadResult } from "./types";

export function UploadScreen({
  onUploaded,
  onAuthExpired,
}: {
  onUploaded: (result: UploadResult) => void;
  onAuthExpired: () => void;
}) {
  const [config, setConfig] = useState<File | null>(null);
  const [versionInfo, setVersionInfo] = useState<File | null>(null);
  const [vendorHint, setVendorHint] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!config || !versionInfo) {
      setError("Both files are required");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      const result = vendorHint.trim()
        ? await uploadDevice(config, versionInfo, vendorHint.trim())
        : await uploadDevice(config, versionInfo);
      onUploaded(result);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthExpired();
        return;
      }
      setError(err instanceof ApiError ? err.message : "Upload failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="card">
      <div style={{ marginBottom: 24 }}>
        <h1>Upload a device</h1>
        <p>Evaluate Cisco, Juniper, AWS, or custom vendor configurations against security standards.</p>
      </div>
      <form onSubmit={handleSubmit} style={{ maxWidth: 540 }}>
        <label>
          Running-config file
          <input
            type="file"
            onChange={(e) => setConfig(e.target.files?.[0] ?? null)}
          />
          {config && (
            <span className="badge badge-red" style={{ marginTop: 4, width: "fit-content" }}>
              Selected: {config.name}
            </span>
          )}
        </label>
        <label>
          Version / hardware info file
          <input
            type="file"
            onChange={(e) => setVersionInfo(e.target.files?.[0] ?? null)}
          />
          {versionInfo && (
            <span className="badge badge-red" style={{ marginTop: 4, width: "fit-content" }}>
              Selected: {versionInfo.name}
            </span>
          )}
        </label>
        <label>
          Vendor hint (optional -- only needed if this vendor isn't recognized automatically)
          <input
            type="text"
            value={vendorHint}
            onChange={(e) => setVendorHint(e.target.value)}
            placeholder="e.g. acme_widgetos"
          />
        </label>
        {error && <p role="alert">{error}</p>}
        <button type="submit" disabled={submitting} className="btn-primary">
          {submitting ? "Evaluating..." : "Evaluate device"}
        </button>
      </form>
    </div>
  );
}
