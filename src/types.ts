export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'warning' | 'error';

export interface TypesPosition {
  line: number;
  column: number;
}

export interface TypesRange {
  start: TypesPosition;
  end: TypesPosition;
}

export interface TypesLocation {
  file: string;
  line: number;
  column: number;
}

export interface TypesFix {
  description: string;
  replacement: string;
  range: TypesRange;
}

export interface TypesVulnerability {
  ruleId: string;
  message: string;
  severity: SeverityLevel;
  location: TypesLocation;
  fix?: TypesFix;
}

export interface VulnerabilitySummary {
  total: number;
  info: number;
  warning: number;
  error: number;
  high: number;
  critical: number;
  medium?: number;
  low?: number;
}

export interface TypesScanResult {
  vulnerabilities: TypesVulnerability[];
  summary: VulnerabilitySummary;
}

export interface VulnerabilityResult {
  id: string;
  severity: SeverityLevel;
  message: string;
  location: TypesLocation;
  rule: string;
  fix?: TypesFix;
} 