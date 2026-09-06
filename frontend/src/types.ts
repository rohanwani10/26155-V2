export interface DeviceIdentity {
  model: string | null;
  serial_number: string | null;
  os_version: string | null;
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
