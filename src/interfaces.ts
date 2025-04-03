export type SupportedLanguage = 'javascript' | 'python' | 'java' | 'csharp';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'warning' | 'error';

export interface Vulnerability {
  ruleId: string;
  message: string;
  severity: Severity;
  line: number;
  column: number;
  file: string;
  remediation?: string;
  fix?: {
    description: string;
    replacement: string;
    range: {
      start: { line: number; column: number };
      end: { line: number; column: number };
    };
  };
}

export interface Rule {
  id: string;
  description: string;
  severity: Severity;
  pattern: string;
  language: SupportedLanguage;
  remediation?: string;
}

export interface ScanOptions {
  languages?: SupportedLanguage[];
  includePaths?: string[];
  excludePaths?: string[];
  rules?: string[];
  enableDynamicAnalysis?: boolean;
  maxFiles?: number;
  customRules?: any[];
  excludeRules?: string[];
  ignorePatterns?: string[];
}

export interface ScanResult {
  vulnerabilities: Vulnerability[];
  scannedFiles?: number;
  totalVulnerabilities?: number;
  duration?: number;
  byLanguage?: Record<SupportedLanguage, number>;
  bySeverity?: Record<Severity, number>;
  summary?: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    error: number;
    warning: number;
    info: number;
  };
}

export interface IExecutionContext {
  log(level: string, ...args: any[]): void;
  recordEvent(eventType: string, data: Record<string, any>): void;
  recordFileAccess(path: string, operation: string): void;
  recordNetworkRequest(url: string, method: string): void;
  recordCommandExecution(command: string): void;
  recordVulnerability(vulnerability: Vulnerability): void;
  getVulnerabilities(): Vulnerability[];
  reset(): void;
  analyzeExecutionPath(): void;
}

export interface ITaintTracker {
  instrumentCode(code: string, language: SupportedLanguage): string;
  markTainted(variableName: string, value: any): void;
  checkSinks(sinkType: string, value: any): void;
  getVulnerabilities(): Vulnerability[];
  reset(): void;
} 