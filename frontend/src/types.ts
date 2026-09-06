export interface DeviceIdentity {
  model: string | null;
  serial_number: string | null;
  os_version: string | null;
  // Cloud-native targets (e.g. AWS Security Groups) substitute these for
  // model/serial/os_version, which don't apply to a non-physical device.
  resource_id?: string | null;
  account?: string | null;
  region?: string | null;
}

export interface Finding {
  control_id: string;
  framework: string;
  title: string;
  severity: string;
  status: "pass" | "fail";
  remediation: string | null;
}

// ISO/IEC 27001 Annex A maps many facts to one control objective, so it's
// evidence toward that objective rather than a pass/fail verdict -- kept as
// a distinct shape so the UI can never mistake it for a line-item check.
export interface FactEvidence {
  fact_id: string;
  title: string;
  satisfied: boolean;
  remediation: string | null;
}

export interface IsoEvidenceFinding {
  control_id: string;
  framework: string;
  title: string;
  evidence: FactEvidence[];
}

export interface UploadResult {
  device_id: string;
  identity: DeviceIdentity;
  findings: Record<string, Finding[]>;
  iso_evidence: IsoEvidenceFinding[];
}

export interface BulkUploadError {
  error: string;
  config_filename: string;
}

export type BulkUploadEntry = UploadResult | BulkUploadError;

export function isBulkUploadError(entry: BulkUploadEntry): entry is BulkUploadError {
  return "error" in entry;
}

export interface BulkUploadResponse {
  results: BulkUploadEntry[];
}

export interface FleetDeviceSummary {
  device_id: string;
  identity: DeviceIdentity | null;
  pass_counts: Record<string, number>;
  fail_counts: Record<string, number>;
}

export interface FleetFrameworkFailure {
  control_id: string;
  title: string;
  severity: string;
  fail_count: number;
}

export interface FleetFrameworkSummary {
  total_pass_count: number;
  total_fail_count: number;
  most_common_failures: FleetFrameworkFailure[];
}

export interface FleetSummary {
  device_count: number;
  devices: FleetDeviceSummary[];
  frameworks: Record<string, FleetFrameworkSummary>;
}

export interface TrainingQueueResponse {
  vendor: string;
  lines: string[];
}

export interface TrainingSuggestion {
  vendor: string;
  line: string;
  fact_id: string | null;
  value: boolean | null;
  rationale: string | null;
  verified: boolean;
  error: string | null;
  doc_enrichment_used: boolean;
}

export interface ChatCitation {
  control_id: string;
  framework: string;
  title: string;
  status: string;
}

export interface ChatExchange {
  question: string;
  answer: string;
  citations: ChatCitation[];
}

export interface ChatHistoryResponse {
  history: ChatExchange[];
}
