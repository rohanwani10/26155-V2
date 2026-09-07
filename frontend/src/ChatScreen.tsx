import { useEffect, useState } from "react";
import { ApiError, getChatHistory, sendChatMessage } from "./api";
import type { ChatExchange } from "./types";

export function ChatScreen({
  deviceId,
  onBack,
  onAuthExpired,
}: {
  deviceId: string;
  onBack: () => void;
  onAuthExpired: () => void;
}) {
  const [history, setHistory] = useState<ChatExchange[]>([]);
  const [question, setQuestion] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const { history } = await getChatHistory(deviceId);
        setHistory(history);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          onAuthExpired();
          return;
        }
        setError("Failed to load chat history");
      } finally {
        setLoaded(true);
      }
    })();
    // Runs once per device -- onAuthExpired is a stable callback from App.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId]);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!question.trim()) return;
    setError(null);
    setSending(true);
    try {
      const exchange = await sendChatMessage(deviceId, question.trim());
      setHistory((prev) => [...prev, exchange]);
      setQuestion("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthExpired();
        return;
      }
      // Most likely cause: no local Ollama instance running.
      setError("Couldn't get an answer (is Ollama running?)");
    } finally {
      setSending(false);
    }
  }

  return (
    <div>
      <div className="flex-between" style={{ marginBottom: 24 }}>
        <h1>Ask about this device</h1>
        <button onClick={onBack} className="btn-dark">
          Back to results
        </button>
      </div>

      {!loaded ? (
        <div className="card">
          <p>Loading chat history...</p>
        </div>
      ) : (
        <section className="card">
          {history.length === 0 ? (
            <p>No questions asked yet.</p>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 16 }}>
              {history.map((exchange, index) => (
                <li key={index} style={{ borderBottom: "1px solid var(--border-light)", paddingBottom: 16 }}>
                  <div className="card card-red" style={{ padding: "12px 18px", marginBottom: 10, borderRadius: "16px" }}>
                    <p style={{ margin: 0, fontWeight: 700, color: "#FFF" }}>
                      <strong>Q:</strong> {exchange.question}
                    </p>
                  </div>
                  <div className="card card-dark" style={{ padding: "16px 20px", borderRadius: "16px" }}>
                    <p style={{ margin: 0, color: "#FFF" }}>
                      <strong>A:</strong> {exchange.answer}
                    </p>
                    {exchange.citations.length > 0 && (
                      <ul style={{ marginTop: 12, paddingLeft: 20, color: "var(--text-light-muted)" }}>
                        {exchange.citations.map((citation) => (
                          <li key={`${citation.framework}-${citation.control_id}`}>
                            <span className="badge badge-red" style={{ marginRight: 6 }}>
                              {citation.framework} {citation.control_id}
                            </span>
                            {citation.title} ({citation.status})
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <form onSubmit={handleSend} className="card" style={{ maxWidth: "100%" }}>
        <label>
          Question
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="e.g. Why did the SSH check fail?"
          />
        </label>
        {error && <p role="alert">{error}</p>}
        <button type="submit" disabled={sending} className="btn-primary">
          {sending ? "Asking..." : "Ask"}
        </button>
      </form>
    </div>
  );
}
