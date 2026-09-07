import { useEffect, useRef, useState } from "react";
import { ApiError, getGlobalChatHistory, sendGlobalChatMessage } from "./api";
import type { ChatExchange } from "./types";

interface PromptCard {
  icon: string;
  title: string;
  desc: string;
  prompt: string;
}

const STARTER_CARDS: PromptCard[] = [
  {
    icon: "🛡️",
    title: "Audit CIS Benchmarks",
    desc: "Show high-severity CIS benchmark failures across fleet",
    prompt: "Show all high-severity CIS benchmark failures across my fleet",
  },
  {
    icon: "⚙️",
    title: "Vendor Training Rules",
    desc: "List custom rules configured for Cisco IOS & Juniper SRX",
    prompt: "What vendor training rules exist for Cisco and Juniper?",
  },
  {
    icon: "📋",
    title: "ISO 27001 Evidence",
    desc: "Summarize ISO 27001 Annex A compliance & evidence status",
    prompt: "Summarize ISO 27001 Annex A compliance status",
  },
  {
    icon: "🔒",
    title: "SSH & Crypto Policies",
    desc: "Which devices are missing SSH version 2 configuration?",
    prompt: "Which devices are missing SSH version 2 configuration?",
  },
];

export function GlobalChatScreen({ onAuthExpired }: { onAuthExpired?: () => void }) {
  const [history, setHistory] = useState<ChatExchange[]>([]);
  const [question, setQuestion] = useState("");
  const [sending, setSending] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [likedMap, setLikedMap] = useState<Record<number, "up" | "down" | null>>({});
  const messagesEndRef = useRef<HTMLDivElement>(null);

  async function loadHistory() {
    try {
      const res = await getGlobalChatHistory();
      setHistory(res.history);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && onAuthExpired) {
        onAuthExpired();
      } else {
        setHistory([]);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadHistory();
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history, sending]);

  async function handleSend(promptText?: string) {
    const textToSend = promptText || question;
    if (!textToSend.trim() || sending) return;

    setSending(true);
    setError(null);

    const tempExchange: ChatExchange = {
      question: textToSend,
      answer: "Analyzing fleet telemetry & vector knowledge base...",
      citations: [],
    };
    setHistory((prev) => [...prev, tempExchange]);
    if (!promptText) setQuestion("");

    try {
      const result = await sendGlobalChatMessage(textToSend);
      setHistory((prev) => [...prev.slice(0, -1), result]);
    } catch (err) {
      setHistory((prev) => prev.slice(0, -1));
      if (err instanceof ApiError && err.status === 401 && onAuthExpired) {
        onAuthExpired();
      } else {
        setError("Failed to generate response. Please try again.");
      }
    } finally {
      setSending(false);
    }
  }

  function handleCopy(text: string, idx: number) {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  }

  function toggleLike(idx: number, type: "up" | "down") {
    setLikedMap((prev) => ({
      ...prev,
      [idx]: prev[idx] === type ? null : type,
    }));
  }

  if (loading) {
    return (
      <div className="agent-loading-state">
        <div className="agent-loading-spinner" />
        <p>Loading UniConfig Agent...</p>
      </div>
    );
  }

  return (
    <div className="agent-chat-layout full-page">
      {/* Header Bar */}
      <header className="agent-header">
        <div className="agent-header-left">
          <div className="agent-title-badge">
            <span className="agent-avatar-dot" />
            <span className="agent-title-text">UniConfig Air-Gapped Agent</span>
          </div>
        </div>

        <div className="agent-header-right">
          <div className="agent-status-pill">
            <span className="agent-status-dot" />
            100% Air-Gapped RAG
          </div>
        </div>
      </header>

      {/* Scrollable Message Flow */}
      <main className="agent-chat-body">
        <div className="agent-chat-content">
          <div className="agent-date-divider">
            <span>TODAY</span>
          </div>

          {history.length === 0 ? (
            <div className="agent-starter-section">
              <h2 className="agent-starter-heading">How can UniConfig Agent help you today?</h2>
              <div className="agent-starter-grid">
                {STARTER_CARDS.map((card, i) => (
                  <button
                    key={i}
                    className="agent-starter-card"
                    onClick={() => handleSend(card.prompt)}
                  >
                    <span className="agent-starter-icon">{card.icon}</span>
                    <span className="agent-starter-title">{card.title}</span>
                    <span className="agent-starter-desc">{card.desc}</span>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="agent-thread">
              {history.map((exchange, idx) => (
                <div key={idx} className="agent-exchange">
                  {/* User Question */}
                  <div className="agent-message-block user-block">
                    <div className="agent-meta">
                      Me <span className="agent-meta-dot">•</span> {idx === history.length - 1 ? "Just now" : `${(history.length - idx) * 2} min ago`}
                    </div>
                    <div className="agent-bubble-user">{exchange.question}</div>
                  </div>

                  {/* Assistant Answer */}
                  <div className="agent-message-block assistant-block">
                    <div className="agent-meta">
                      UniConfig Agent <span className="agent-meta-dot">•</span> {idx === history.length - 1 ? "Just now" : `${(history.length - idx) * 2 - 1} min ago`}
                    </div>
                    <div className="agent-assistant-body">
                      {exchange.answer}
                    </div>

                    {/* Citations */}
                    {exchange.citations && exchange.citations.length > 0 && (
                      <div className="agent-citations-container">
                        <div className="agent-citations-label">Knowledge Citations</div>
                        <div className="agent-citations-pills">
                          {exchange.citations.map((cit, cIdx) => (
                            <span key={cIdx} className="agent-citation-chip">
                              📍 [{cit.framework}] {cit.control_id} • {cit.title}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Action Bar (Thumb up, Thumb down, Copy) */}
                    <div className="agent-actions-bar">
                      <button
                        className={`agent-action-btn ${likedMap[idx] === "up" ? "active" : ""}`}
                        onClick={() => toggleLike(idx, "up")}
                        title="Helpful"
                      >
                        👍
                      </button>
                      <button
                        className={`agent-action-btn ${likedMap[idx] === "down" ? "active" : ""}`}
                        onClick={() => toggleLike(idx, "down")}
                        title="Not helpful"
                      >
                        👎
                      </button>
                      <button
                        className="agent-action-btn"
                        onClick={() => handleCopy(exchange.answer, idx)}
                        title="Copy message"
                      >
                        {copiedIdx === idx ? "✓" : "📋"}
                      </button>
                    </div>
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>
      </main>

      {/* Floating Card Input Area */}
      <footer className="agent-footer-wrapper">
        <div className="agent-footer-inner">
          {error && <div className="agent-error-banner">{error}</div>}

          <form
            className="agent-input-card"
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
          >
            {/* Textarea Input */}
            <textarea
              className="agent-input-textarea"
              rows={3}
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              placeholder="Ask UniConfig Agent anything about vendor compliance or training..."
              disabled={sending}
            />

            {/* Bottom row of card */}
            <div className="agent-card-bottom">
              <div className="agent-pills-left">
                <span className="agent-model-tag">🤖 Local RAG Model</span>
              </div>

              <div className="agent-actions-right">
                <button
                  type="submit"
                  className="agent-send-button"
                  disabled={sending || !question.trim()}
                >
                  <span>Send</span>
                  <span className="agent-send-shortcut">↵</span>
                </button>
              </div>
            </div>
          </form>

          <div className="agent-footer-disclaimer">
            UniConfig Agent is running on local air-gapped models.
          </div>
        </div>
      </footer>
    </div>
  );
}
