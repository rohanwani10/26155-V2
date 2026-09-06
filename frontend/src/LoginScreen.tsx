import { useState } from "react";
import { ApiError, login } from "./api";

export function LoginScreen({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [credential, setCredential] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await login(credential);
      onLoggedIn();
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError("Too many failed attempts, try again shortly");
      } else if (err instanceof ApiError && err.status === 401) {
        setError("Invalid password");
      } else {
        setError("Login failed");
      }
    }
  }

  return (
    <div>
      <h1>Log in</h1>
      <form onSubmit={handleSubmit}>
        <label>
          Master password
          <input
            type="password"
            value={credential}
            onChange={(e) => setCredential(e.target.value)}
          />
        </label>
        {error && <p role="alert">{error}</p>}
        <button type="submit">Log in</button>
      </form>
    </div>
  );
}
