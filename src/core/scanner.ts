import {
  Rule,
  ScanOptions,
  ScanResult,
  SupportedLanguage,
  Vulnerability
} from '../interfaces';
import { loadRules } from '../rules/ruleLoader';
import { getParser } from '../parsers';

export class Scanner {
  private rules: Rule[] = [];

  constructor(private options: ScanOptions = {}) {
    this.loadRules();
  }

  private loadRules(): void {
    const allRules = loadRules();
    
    // Filter rules based on options
    if (this.options.rules && this.options.rules.length > 0) {
      this.rules = allRules.filter((rule: Rule) => this.options.rules?.includes(rule.id));
    } else if (this.options.excludeRules && this.options.excludeRules.length > 0) {
      this.rules = allRules.filter((rule: Rule) => !this.options.excludeRules?.includes(rule.id));
    } else {
      this.rules = allRules;
    }

    // Add custom rules if provided
    if (this.options.customRules && this.options.customRules.length > 0) {
      this.rules = [...this.rules, ...this.options.customRules];
    }
  }

  public scan(code: string, language: SupportedLanguage): ScanResult {
    // Get language-specific parser
    const parser = getParser(language);
    
    // Parse the code
    const parsedCode = parser.parse(code);
    
    // Apply rules
    const vulnerabilities: Vulnerability[] = [];
    
    for (const rule of this.rules) {
      try {
        const ruleVulnerabilities = rule.check(code, language);
        vulnerabilities.push(...ruleVulnerabilities);
      } catch (error) {
        console.error(`Error applying rule ${rule.id}:`, error);
      }
    }

    // Create summary
    const summary = {
      total: vulnerabilities.length,
      info: vulnerabilities.filter(v => v.severity === 'info').length,
      warning: vulnerabilities.filter(v => v.severity === 'warning').length,
      error: vulnerabilities.filter(v => v.severity === 'error').length,
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length
    };

    return {
      vulnerabilities,
      summary
    };
  }

  public scanMultiple(files: { path: string; content: string; language: SupportedLanguage }[]): { [path: string]: ScanResult } {
    const results: { [path: string]: ScanResult } = {};

    for (const file of files) {
      results[file.path] = this.scan(file.content, file.language);
    }

    return results;
  }
} 