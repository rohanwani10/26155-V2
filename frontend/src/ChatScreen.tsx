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
      <h1>Ask about this device</h1>
      <button onClick={onBack}>Back to results</button>

      {!loaded ? (
        <p>Loading chat history...</p>
      ) : (
        <section>
          {history.length === 0 ? (
            <p>No questions asked yet.</p>
          ) : (
            <ul>
              {history.map((exchange, index) => (
                <li key={index}>
                  <p>
                    <strong>Q:</strong> {exchange.question}
                  </p>
                  <p>
                    <strong>A:</strong> {exchange.answer}
                  </p>
                  {exchange.citations.length > 0 && (
                    <ul>
                      {exchange.citations.map((citation) => (
                        <li key={`${citation.framework}-${citation.control_id}`}>
                          {citation.framework} {citation.control_id}: {citation.title} (
                          {citation.status})
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <form onSubmit={handleSend}>
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
        <button type="submit" disabled={sending}>
          {sending ? "Asking..." : "Ask"}
        </button>
      </form>
    </div>
  );
}
