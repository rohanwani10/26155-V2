import { useState } from "react";
import { ApiError, setup } from "./api";

export function SetupScreen({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    try {
      const { recovery_key } = await setup(password);
      setRecoveryKey(recovery_key);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Setup failed");
    }
  }

  if (recoveryKey) {
    return (
      <div style={{ maxWidth: 540, margin: "40px auto" }} className="card card-yellow">
        <h1>Save your recovery key</h1>
        <p>
          This is the only time this key will be shown. Store it somewhere
          safe -- it's the only way to recover your data if you forget your
          master password.
        </p>
        <pre data-testid="recovery-key">{recoveryKey}</pre>
        <button onClick={onDone} className="btn-dark" style={{ width: "100%", marginTop: 16 }}>
          I've saved it, continue to login
        </button>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 440, margin: "40px auto" }} className="card card-dark">
      <h1 style={{ color: "#FFF" }}>Set up your admin account</h1>
      <p style={{ color: "var(--text-light-muted)" }}>
        Initialize master encryption and security credentials
      </p>
      <form onSubmit={handleSubmit} style={{ maxWidth: "100%" }}>
        <label style={{ color: "#FFF" }}>
          Master password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <label style={{ color: "#FFF" }}>
          Confirm password
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </label>
        {error && <p role="alert">{error}</p>}
        <button type="submit" className="btn-primary" style={{ width: "100%", marginTop: 8 }}>
          Create account
        </button>
      </form>
    </div>
  );
}
