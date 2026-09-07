import { useEffect, useState } from "react";
import { getDevice, getMe, getSetupStatus, logout } from "./api";
import { BulkUploadScreen } from "./BulkUploadScreen";
import { ChatScreen } from "./ChatScreen";
import { FleetDashboardScreen } from "./FleetDashboardScreen";
import { LandingScreen } from "./LandingScreen";
import { LoginScreen } from "./LoginScreen";
import { Nav, type NavTarget } from "./Nav";
import { ResultsScreen } from "./ResultsScreen";
import { SetupScreen } from "./SetupScreen";
import { TrainingScreen } from "./TrainingScreen";
import type { UploadResult } from "./types";
import { UploadScreen } from "./UploadScreen";

type Screen =
  | { name: "loading" }
  | { name: "setup" }
  | { name: "landing" }
  | { name: "login" }
  | { name: "upload" }
  | { name: "bulk-upload" }
  | { name: "fleet" }
  | { name: "training" }
  | { name: "results"; result: UploadResult }
  | { name: "chat"; deviceId: string };

const NAV_TARGETS: Record<string, NavTarget> = {
  upload: "upload",
  "bulk-upload": "bulk-upload",
  fleet: "fleet",
  training: "training",
};

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

  function navigate(target: NavTarget) {
    switch (target) {
      case "landing":
        setScreen({ name: "landing" });
        break;
      case "upload":
        setScreen({ name: "upload" });
        break;
      case "bulk-upload":
        setScreen({ name: "bulk-upload" });
        break;
      case "fleet":
        setScreen({ name: "fleet" });
        break;
      case "training":
        setScreen({ name: "training" });
        break;
    }
  }

  function viewDevice(deviceId: string) {
    getDevice(deviceId)
      .then((result) => setScreen({ name: "results", result }))
      .catch(() => goToLogin());
  }

  const withNav = (content: React.ReactNode) => (
    <div>
      <Nav current={NAV_TARGETS[screen.name] ?? null} onNavigate={navigate} onLogout={handleLogout} />
      {content}
    </div>
  );

  switch (screen.name) {
    case "loading":
      return null;
    case "setup":
      return <SetupScreen onDone={goToLogin} />;
    case "landing":
      return <LandingScreen onGoToLogin={goToLogin} />;
    case "login":
      return (
        <LoginScreen
          onLoggedIn={() => setScreen({ name: "upload" })}
          onBackToLanding={() => setScreen({ name: "landing" })}
        />
      );
    case "upload":
      return withNav(
        <UploadScreen
          onUploaded={(result) => setScreen({ name: "results", result })}
          onAuthExpired={goToLogin}
        />,
      );
    case "bulk-upload":
      return withNav(
        <BulkUploadScreen onViewDevice={viewDevice} onAuthExpired={goToLogin} />,
      );
    case "fleet":
      return withNav(
        <FleetDashboardScreen onViewDevice={viewDevice} onAuthExpired={goToLogin} />,
      );
    case "training":
      return withNav(<TrainingScreen onAuthExpired={goToLogin} />);
    case "results":
      return withNav(
        <ResultsScreen
          result={screen.result}
          onUploadAnother={() => setScreen({ name: "upload" })}
          onAuthExpired={goToLogin}
          onChat={(deviceId) => setScreen({ name: "chat", deviceId })}
        />,
      );
    case "chat":
      return withNav(
        <ChatScreen
          deviceId={screen.deviceId}
          onBack={() => viewDevice(screen.deviceId)}
          onAuthExpired={goToLogin}
        />,
      );
  }
}
