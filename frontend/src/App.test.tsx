import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { ApiError } from "./api";
import type { UploadResult } from "./types";

const api = vi.hoisted(() => ({
  getSetupStatus: vi.fn(),
  getMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  uploadDevice: vi.fn(),
  fetchReportPdf: vi.fn(),
  setup: vi.fn(),
}));

vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return { ...actual, ...api };
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe("session bootstrap", () => {
  it("sends an authenticated-but-session-expired user to the login screen", async () => {
    api.getSetupStatus.mockResolvedValue({ setup_complete: true });
    api.getMe.mockRejectedValue(new ApiError(401, "Not authenticated"));

    render(<App />);

    expect(await screen.findByRole("heading", { name: /log in/i })).toBeInTheDocument();
  });

  it("goes straight to the upload screen when a session is already active", async () => {
    api.getSetupStatus.mockResolvedValue({ setup_complete: true });
    api.getMe.mockResolvedValue({ authenticated: true });

    render(<App />);

    expect(
      await screen.findByRole("heading", { name: /upload a device/i }),
    ).toBeInTheDocument();
  });
});

describe("device upload flow", () => {
  it("renders findings and identity after a successful upload", async () => {
    api.getSetupStatus.mockResolvedValue({ setup_complete: true });
    api.getMe.mockResolvedValue({ authenticated: true });
    const result: UploadResult = {
      device_id: "abc123",
      identity: { model: "WS-C2960", serial_number: "FOC123", os_version: "15.0" },
      findings: {
        CIS: [
          {
            control_id: "CIS-4.1",
            framework: "CIS",
            title: "Use SSH version 2 only",
            severity: "high",
            status: "fail",
            remediation: "Configure: ip ssh version 2",
          },
        ],
      },
      iso_evidence: [],
    };
    api.uploadDevice.mockResolvedValue(result);

    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", { name: /upload a device/i });

    const configFile = new File(["config"], "running-config.txt");
    const versionFile = new File(["version"], "version.txt");
    const fileInputs = document.querySelectorAll('input[type="file"]');
    await user.upload(fileInputs[0] as HTMLInputElement, configFile);
    await user.upload(fileInputs[1] as HTMLInputElement, versionFile);
    await user.click(screen.getByRole("button", { name: /evaluate device/i }));

    await waitFor(() => expect(api.uploadDevice).toHaveBeenCalledWith(configFile, versionFile));
    expect(await screen.findByText(/WS-C2960/)).toBeInTheDocument();
    expect(screen.getByText("CIS-4.1")).toBeInTheDocument();
    expect(screen.getByText("Configure: ip ssh version 2")).toBeInTheDocument();
  });
});
