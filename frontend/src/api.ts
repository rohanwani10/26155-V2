import type {
  BulkUploadResponse,
  ChatExchange,
  ChatHistoryResponse,
  FleetSummary,
  TrainingQueueResponse,
  TrainingSuggestion,
  UploadResult,
} from "./types";

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

export function uploadDevice(config: File, versionInfo: File, vendorHint?: string) {
  const body = new FormData();
  body.append("config", config);
  body.append("version_info", versionInfo);
  if (vendorHint) body.append("vendor_hint", vendorHint);
  return request<UploadResult>("/api/devices", { method: "POST", body });
}

// Positional pairing: configs[0] goes with versionInfos[0], etc -- mirrors
// the backend's own "two same-length lists" contract (see devices.py).
export function uploadDevicesBulk(configs: File[], versionInfos: File[], vendorHint?: string) {
  const body = new FormData();
  configs.forEach((file) => body.append("configs", file));
  versionInfos.forEach((file) => body.append("version_infos", file));
  if (vendorHint) body.append("vendor_hint", vendorHint);
  return request<BulkUploadResponse>("/api/devices/bulk", { method: "POST", body });
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

// The stored device record has no device_id field inside it (that's only
// the store's key/path param) -- stitched back in here so callers get the
// same UploadResult shape the upload endpoints already return.
export async function getDevice(deviceId: string): Promise<UploadResult> {
  const record = await request<Omit<UploadResult, "device_id">>(`/api/devices/${deviceId}`);
  return { device_id: deviceId, ...record };
}

export function getFleetSummary() {
  return request<FleetSummary>("/api/fleet/summary");
}

export function getTrainingQueue(vendor: string) {
  return request<TrainingQueueResponse>(
    `/api/training/queue?vendor=${encodeURIComponent(vendor)}`,
  );
}

export function getTrainingSuggestion(vendor: string, line: string) {
  return request<TrainingSuggestion>(
    `/api/training/suggestions?vendor=${encodeURIComponent(vendor)}&line=${encodeURIComponent(line)}`,
  );
}

export function confirmTrainingMapping(
  vendor: string,
  line: string,
  factId: string,
  value: boolean,
) {
  return request<{ ok: boolean }>("/api/training/mappings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ vendor, line, fact_id: factId, value }),
  });
}

export function sendChatMessage(deviceId: string, question: string) {
  return request<ChatExchange>(`/api/devices/${deviceId}/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question }),
  });
}

export function getChatHistory(deviceId: string) {
  return request<ChatHistoryResponse>(`/api/devices/${deviceId}/chat`);
}
