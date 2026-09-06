import { useState } from "react";
import { ApiError, uploadDevicesBulk } from "./api";
import { isBulkUploadError, type BulkUploadEntry } from "./types";

export function BulkUploadScreen({
  onViewDevice,
  onAuthExpired,
}: {
  onViewDevice: (deviceId: string) => void;
  onAuthExpired: () => void;
}) {
  const [configs, setConfigs] = useState<File[]>([]);
  const [versionInfos, setVersionInfos] = useState<File[]>([]);
  const [vendorHint, setVendorHint] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [results, setResults] = useState<BulkUploadEntry[] | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (configs.length === 0 || versionInfos.length === 0) {
      setError("Select at least one config file and one version-info file");
      return;
    }
    if (configs.length !== versionInfos.length) {
      setError(
        `Selected ${configs.length} config file(s) but ${versionInfos.length} version-info file(s) -- ` +
          "they're paired positionally, so the counts must match",
      );
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      const { results } = await uploadDevicesBulk(
        configs,
        versionInfos,
        vendorHint.trim() || undefined,
      );
      setResults(results);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthExpired();
        return;
      }
      setError(err instanceof ApiError ? err.message : "Bulk upload failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <h1>Bulk upload devices</h1>
      <p>
        Select multiple config files and the same number of version/hardware
        info files -- they're paired positionally in selection order (the
        first config goes with the first version-info file, and so on).
      </p>
      <form onSubmit={handleSubmit}>
        <label>
          Running-config files
          <input
            type="file"
            multiple
            onChange={(e) => setConfigs(Array.from(e.target.files ?? []))}
          />
        </label>
        <label>
          Version / hardware info files
          <input
            type="file"
            multiple
            onChange={(e) => setVersionInfos(Array.from(e.target.files ?? []))}
          />
        </label>
        <label>
          Vendor hint (optional, applies to the whole batch)
          <input
            type="text"
            value={vendorHint}
            onChange={(e) => setVendorHint(e.target.value)}
            placeholder="e.g. acme_widgetos"
          />
        </label>
        {error && <p role="alert">{error}</p>}
        <button type="submit" disabled={submitting}>
          {submitting ? "Evaluating..." : "Evaluate devices"}
        </button>
      </form>

      {results && (
        <section>
          <h2>
            Results: {results.filter((r) => !isBulkUploadError(r)).length} / {results.length}{" "}
            devices evaluated successfully
          </h2>
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {results.map((result, index) =>
                isBulkUploadError(result) ? (
                  <tr key={index}>
                    <td>{result.config_filename}</td>
                    <td role="alert">{result.error}</td>
                    <td></td>
                  </tr>
                ) : (
                  <tr key={result.device_id}>
                    <td>{result.identity.model ?? result.identity.resource_id ?? result.device_id}</td>
                    <td>Evaluated</td>
                    <td>
                      <button onClick={() => onViewDevice(result.device_id)}>
                        View results
                      </button>
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
