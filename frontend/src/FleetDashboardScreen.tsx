import { useEffect, useState } from "react";
import { ApiError, getFleetSummary } from "./api";
import type { FleetSummary } from "./types";

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
        setFramework(Object.keys(result.frameworks)[0] ?? null);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          onAuthExpired();
          return;
        }
        setError("Failed to load fleet summary");
      }
    })();
    // Runs once on mount -- onAuthExpired is a stable callback from App.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (error) return <p role="alert">{error}</p>;
  if (!summary) return <p>Loading fleet summary...</p>;

  return (
    <div>
      <h1>Fleet dashboard</h1>
      <p>{summary.device_count} device(s) evaluated</p>

      {summary.device_count === 0 ? (
        <p>No devices uploaded yet.</p>
      ) : (
        <>
          <label htmlFor="fleet-framework-select">Framework</label>
          <select
            id="fleet-framework-select"
            value={framework ?? ""}
            onChange={(e) => setFramework(e.target.value)}
          >
            {Object.keys(summary.frameworks).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>

          {framework && (
            <section>
              <h2>{framework} fleet totals</h2>
              <p>
                {summary.frameworks[framework].total_pass_count} passed /{" "}
                {summary.frameworks[framework].total_fail_count} failed across
                the fleet
              </p>
              <h3>Most common failures</h3>
              {summary.frameworks[framework].most_common_failures.length === 0 ? (
                <p>No failures.</p>
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
                    {summary.frameworks[framework].most_common_failures.map((f) => (
                      <tr key={f.control_id}>
                        <td>{f.control_id}</td>
                        <td>{f.title}</td>
                        <td>{f.severity}</td>
                        <td>{f.fail_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          )}

          <section>
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
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {summary.devices.map((device) => (
                  <tr key={device.device_id}>
                    <td>
                      {device.identity?.model ??
                        device.identity?.resource_id ??
                        device.device_id}
                    </td>
                    {framework && (
                      <>
                        <td>{device.pass_counts[framework] ?? 0}</td>
                        <td>{device.fail_counts[framework] ?? 0}</td>
                      </>
                    )}
                    <td>
                      <button onClick={() => onViewDevice(device.device_id)}>
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
