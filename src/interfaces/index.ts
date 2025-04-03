export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: 'info' | 'warning' | 'error' | 'critical' | 'high' | 'medium' | 'low';
  category: string;
  references?: string[];
  check: (code: string, language: SupportedLanguage, options?: any) => Vulnerability[];
}

export interface Vulnerability {
  ruleId: string;
  message: string;
  severity: 'info' | 'warning' | 'error' | 'critical' | 'high' | 'medium' | 'low';
  line: number;
  column: number;
  file: string;
  endLine?: number;
  endColumn?: number;
  fix?: Fix;
  remediation?: string;
}

export interface Fix {
  description: string;
  replacement: string;
  range: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
}

export type SupportedLanguage = 'javascript' | 'python' | 'java' | 'csharp';

export interface ScanResult {
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    info: number;
    warning: number;
    error: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface ScanOptions {
  rules?: string[];
  excludeRules?: string[];
  customRules?: Rule[];
  ignorePatterns?: string[];
}

export interface ScannerConfig {
  blockOnCritical: boolean;
  blockOnError: boolean;
  scanOnSave: boolean;
  scanOnType: boolean;
  enablePreCommitHook: boolean;
  enablePrePushHook: boolean;
  customRulesPath?: string;
  ignorePatterns: string[];
}

export interface RuleSet {
  [id: string]: Rule;
} 