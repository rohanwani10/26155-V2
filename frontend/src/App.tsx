import { useEffect, useState } from "react";
import { getMe, getSetupStatus, logout } from "./api";
import { LoginScreen } from "./LoginScreen";
import { ResultsScreen } from "./ResultsScreen";
import { SetupScreen } from "./SetupScreen";
import type { UploadResult } from "./types";
import { UploadScreen } from "./UploadScreen";

type Screen =
  | { name: "loading" }
  | { name: "setup" }
  | { name: "login" }
  | { name: "upload" }
  | { name: "results"; result: UploadResult };

export default function App() {
  const [screen, setScreen] = useState<Screen>({ name: "loading" });

  useEffect(() => {
    (async () => {
      const { setup_complete } = await getSetupStatus();
      if (!setup_complete) {
        setScreen({ name: "setup" });
        return;
      }
      try {
        await getMe();
        setScreen({ name: "upload" });
      } catch {
        setScreen({ name: "login" });
      }
    })();
  }, []);

  function goToLogin() {
    setScreen({ name: "login" });
  }

  async function handleLogout() {
    await logout();
    goToLogin();
  }

  switch (screen.name) {
    case "loading":
      return null;
    case "setup":
      return <SetupScreen onDone={goToLogin} />;
    case "login":
      return <LoginScreen onLoggedIn={() => setScreen({ name: "upload" })} />;
    case "upload":
      return (
        <div>
          <button onClick={handleLogout}>Log out</button>
          <UploadScreen
            onUploaded={(result) => setScreen({ name: "results", result })}
            onAuthExpired={goToLogin}
          />
        </div>
      );
    case "results":
      return (
        <div>
          <button onClick={handleLogout}>Log out</button>
          <ResultsScreen
            result={screen.result}
            onUploadAnother={() => setScreen({ name: "upload" })}
            onAuthExpired={goToLogin}
          />
        </div>
      );
  }
}
