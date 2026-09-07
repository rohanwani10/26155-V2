import { useState } from "react";
import {
  ApiError,
  confirmTrainingMapping,
  getTrainingQueue,
  getTrainingSuggestion,
} from "./api";
import type { TrainingSuggestion } from "./types";

interface LineState {
  factId: string;
  value: boolean;
  suggestion: TrainingSuggestion | null;
  suggestionLoading: boolean;
  suggestionError: string | null;
  confirmed: boolean;
}

function emptyLineState(): LineState {
  return {
    factId: "",
    value: true,
    suggestion: null,
    suggestionLoading: false,
    suggestionError: null,
    confirmed: false,
  };
}

export function TrainingScreen({ onAuthExpired }: { onAuthExpired: () => void }) {
  const [vendor, setVendor] = useState("");
  const [lines, setLines] = useState<string[] | null>(null);
  const [lineState, setLineState] = useState<Record<string, LineState>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function updateLine(line: string, patch: Partial<LineState>) {
    setLineState((prev) => ({
      ...prev,
      [line]: { ...(prev[line] ?? emptyLineState()), ...patch },
    }));
  }

  async function loadQueue(e: React.FormEvent) {
    e.preventDefault();
    if (!vendor.trim()) {
      setError("Enter a vendor name");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const { lines } = await getTrainingQueue(vendor.trim());
      setLines(lines);
      setLineState({});
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthExpired();
        return;
      }
      setError("Failed to load the training queue");
    } finally {
      setLoading(false);
    }
  }

  async function handleGetSuggestion(line: string) {
    updateLine(line, { suggestionLoading: true, suggestionError: null });
    try {
      const suggestion = await getTrainingSuggestion(vendor.trim(), line);
      updateLine(line, {
        suggestion,
        suggestionLoading: false,
        factId: suggestion.fact_id ?? "",
        value: suggestion.value ?? true,
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthExpired();
        return;
      }
      // Most likely cause: no local Ollama instance running -- suggestions
      // are an assist, not a requirement, so this never blocks the admin
      // from mapping the line manually below.
      updateLine(line, {
        suggestionLoading: false,
        suggestionError: "Couldn't get an AI suggestion (is Ollama running?)",
      });
    }
  }

  async function handleConfirm(line: string) {
    const state = lineState[line] ?? emptyLineState();
    if (!state.factId.trim()) {
      updateLine(line, { suggestionError: "Enter a fact_id to confirm" });
      return;
    }
    try {
      await confirmTrainingMapping(vendor.trim(), line, state.factId.trim(), state.value);
      updateLine(line, { confirmed: true });
      setLines((prev) => (prev ? prev.filter((l) => l !== line) : prev));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthExpired();
        return;
      }
      updateLine(line, {
        suggestionError: err instanceof ApiError ? err.message : "Failed to confirm mapping",
      });
    }
  }

  return (
    <div>
      <div className="card">
        <h1>Vendor training</h1>
        <p>
          Upload an unrecognized vendor's config with a vendor hint (see the
          Upload screen) to queue its unrecognized lines here, then map each
          one to a security category. Confirmed mappings become permanent,
          reusable rules for that vendor -- future uploads evaluate them
          automatically.
        </p>
        <form onSubmit={loadQueue} style={{ maxWidth: 440 }}>
          <label>
            Vendor
            <input
              type="text"
              value={vendor}
              onChange={(e) => setVendor(e.target.value)}
              placeholder="e.g. acme_widgetos"
            />
          </label>
          {error && <p role="alert">{error}</p>}
          <button type="submit" disabled={loading} className="btn-primary">
            {loading ? "Loading..." : "Load queue"}
          </button>
        </form>
      </div>

      {lines && (
        <section className="card">
          <h2>Unrecognized lines for '{vendor.trim()}'</h2>
          {lines.length === 0 ? (
            <p>Nothing queued for this vendor.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Config line</th>
                  <th>Suggestion</th>
                  <th>fact_id</th>
                  <th>Value</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {lines.map((line) => {
                  const state = lineState[line] ?? emptyLineState();
                  return (
                    <tr key={line}>
                      <td>
                        <code>{line}</code>
                      </td>
                      <td>
                        {state.suggestion ? (
                          <div style={{ fontSize: "0.88rem" }}>
                            <p style={{ margin: 0, fontWeight: 700 }}>
                              <span className="badge badge-yellow">
                                {state.suggestion.fact_id ?? "(unparseable)"} = {String(state.suggestion.value)}
                              </span>{" "}
                              {state.suggestion.verified ? "(verified)" : "(unverified)"}
                            </p>
                            {state.suggestion.rationale && <p style={{ margin: "4px 0 0 0" }}>{state.suggestion.rationale}</p>}
                            {state.suggestion.doc_enrichment_used && (
                              <p style={{ margin: "4px 0 0 0", color: "var(--text-muted)" }}>Improved using fetched vendor documentation.</p>
                            )}
                            {state.suggestion.error && <p role="alert">{state.suggestion.error}</p>}
                          </div>
                        ) : (
                          <button
                            onClick={() => handleGetSuggestion(line)}
                            disabled={state.suggestionLoading}
                            className="btn-dark"
                          >
                            {state.suggestionLoading ? "Asking..." : "Get AI suggestion"}
                          </button>
                        )}
                        {state.suggestionError && <p role="alert">{state.suggestionError}</p>}
                      </td>
                      <td>
                        <input
                          type="text"
                          value={state.factId}
                          onChange={(e) => updateLine(line, { factId: e.target.value })}
                          placeholder="fact_id"
                        />
                      </td>
                      <td>
                        <label style={{ flexDirection: "row", alignItems: "center" }}>
                          <input
                            type="checkbox"
                            checked={state.value}
                            onChange={(e) => updateLine(line, { value: e.target.checked })}
                            style={{ width: "auto", cursor: "pointer" }}
                          />
                          true
                        </label>
                      </td>
                      <td>
                        <button onClick={() => handleConfirm(line)} className="btn-primary">
                          Confirm mapping
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>
      )}
    </div>
  );
}
