import type { UploadResult } from "./types";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: "include", ...init });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body.detail ?? res.statusText);
  }
  return res.json() as Promise<T>;
}

export function getSetupStatus() {
  return request<{ setup_complete: boolean }>("/api/setup/status");
}

export function setup(password: string) {
  return request<{ recovery_key: string }>("/api/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
}

export function login(credential: string) {
  return request<{ ok: boolean }>("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ credential }),
  });
}

export function logout() {
  return request<{ ok: boolean }>("/api/logout", { method: "POST" });
}

export function getMe() {
  return request<{ authenticated: boolean }>("/api/me");
}

export function uploadDevice(config: File, versionInfo: File) {
  const body = new FormData();
  body.append("config", config);
  body.append("version_info", versionInfo);
  return request<UploadResult>("/api/devices", { method: "POST", body });
}

export async function fetchReportPdf(deviceId: string): Promise<Blob> {
  const res = await fetch(`/api/devices/${deviceId}/report.pdf`, {
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError(res.status, "Failed to fetch report");
  }
  return res.blob();
}
