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
      const result = await uploadDevice(config, versionInfo);
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
    <div>
      <h1>Upload a device</h1>
      <form onSubmit={handleSubmit}>
        <label>
          Running-config file
          <input
            type="file"
            onChange={(e) => setConfig(e.target.files?.[0] ?? null)}
          />
        </label>
        <label>
          Version / hardware info file
          <input
            type="file"
            onChange={(e) => setVersionInfo(e.target.files?.[0] ?? null)}
          />
        </label>
        {error && <p role="alert">{error}</p>}
        <button type="submit" disabled={submitting}>
          {submitting ? "Evaluating..." : "Evaluate device"}
        </button>
      </form>
    </div>
  );
}
