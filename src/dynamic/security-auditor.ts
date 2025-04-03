import * as fs from 'fs';
import * as path from 'path';
import { SupportedLanguage, Vulnerability } from '../interfaces';
import { DependencyChecker } from './dependency-checker';
import { RuntimeAnalyzer } from './runtime-analyzer';

// Define Severity type locally to avoid import errors
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'warning' | 'error';

export interface AuditOptions {
  includeDependencies?: boolean;
  includeDynamicAnalysis?: boolean;
  includeStaticAnalysis?: boolean;
  outputFormat?: 'json' | 'html' | 'md' | 'text';
  outputFile?: string;
  scanDependencies?: boolean;
  maxFileSizeKb?: number;
  ignorePatterns?: string[];
  severityThreshold?: Severity;
  includeRemediation?: boolean;
  includeSource?: boolean;
  maxVulnerabilities?: number;
  includeStatistics?: boolean;
  showRecommendations?: boolean;
  minSeverity?: Severity;
}

export interface AuditSummary {
  totalFiles: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  byLanguage: Record<SupportedLanguage, number>;
  topVulnerableFiles: { file: string; count: number }[];
  topCategories: { category: string; count: number }[];
  recommendations: string[];
  vulnerabilities?: Vulnerability[];
  summary?: {
    total: number;
    critical: number;
    high: number;
    error: number;
    warning: number;
    info: number;
  };
}

/**
 * Comprehensive security auditor that combines static analysis, 
 * dynamic analysis and dependency checking
 */
export class SecurityAuditor {
  private runtimeAnalyzer: RuntimeAnalyzer;
  private dependencyChecker: DependencyChecker;
  private vulnerabilities: Vulnerability[] = [];
  private auditSummary: AuditSummary;
  
  constructor(private options: AuditOptions = {}) {
    this.options = {
      includeDependencies: true,
      includeDynamicAnalysis: true,
      includeStaticAnalysis: true,
      outputFormat: 'text',
      scanDependencies: true,
      maxFileSizeKb: 1024, // 1MB
      ignorePatterns: ['node_modules', 'dist', 'build', '.git'],
      severityThreshold: 'info',
      includeRemediation: true,
      includeSource: false,
      maxVulnerabilities: 1000,
      includeStatistics: true,
      showRecommendations: true,
      ...options
    };
    
    this.runtimeAnalyzer = new RuntimeAnalyzer();
    this.dependencyChecker = new DependencyChecker();
    
    this.auditSummary = {
      totalFiles: 0,
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        warning: 0,
        error: 0
      },
      byCategory: {},
      byLanguage: {
        javascript: 0,
        python: 0,
        java: 0,
        csharp: 0
      },
      topVulnerableFiles: [],
      topCategories: [],
      recommendations: []
    };
  }
  
  /**
   * Perform a comprehensive security audit on a codebase
   */
  public async auditCodebase(
    directory: string, 
    staticVulnerabilities: Vulnerability[] = [],
    options: AuditOptions = {}
  ): Promise<AuditSummary> {
    // Merge options with defaults
    const mergedOptions: AuditOptions = {
      includeDependencies: true,
      includeDynamicAnalysis: true,
      includeStaticAnalysis: true,
      outputFormat: 'text',
      maxFileSizeKb: 500,
      ignorePatterns: ['node_modules', 'dist', 'build', '.git'],
      severityThreshold: 'low',
      includeRemediation: true,
      ...this.options,
      ...options
    };
    
    try {
      // Reset state
      this.vulnerabilities = [];
      
      // Include static vulnerabilities if provided
      if (mergedOptions.includeStaticAnalysis && staticVulnerabilities.length > 0) {
        this.vulnerabilities.push(...staticVulnerabilities);
      }
      
      // Scan for dynamic vulnerabilities
      if (mergedOptions.includeDynamicAnalysis) {
        const dynamicVulnerabilities = await this.performDynamicAnalysis(directory);
        this.vulnerabilities.push(...dynamicVulnerabilities);
      }
      
      // Check dependencies
      if (mergedOptions.includeDependencies) {
        const dependencyVulnerabilities = await this.checkDependencies(directory);
        this.vulnerabilities.push(...dependencyVulnerabilities);
      }
      
      // Process all vulnerabilities
      this.processVulnerabilities(this.vulnerabilities);
      
      // Filter by severity threshold if specified
      if (mergedOptions.severityThreshold) {
        this.vulnerabilities = this.filterBySeverity(this.vulnerabilities, mergedOptions.severityThreshold);
      }
      
      // Generate audit summary
      this.auditSummary = this.generateSummary(this.vulnerabilities);
      
      // Generate recommendations
      if (mergedOptions.showRecommendations) {
        this.auditSummary.recommendations = this.generateRecommendations();
      }
      
      // Generate and save report if output file specified
      if (mergedOptions.outputFile) {
        // Map 'md' format to 'markdown' for consistency
        let format: 'json' | 'html' | 'markdown' | 'text' = 'text';
        
        if (mergedOptions.outputFormat === 'json') {
          format = 'json';
        } else if (mergedOptions.outputFormat === 'html') {
          format = 'html';
        } else if (mergedOptions.outputFormat === 'md') {
          format = 'markdown';
        }
        
        this.saveReport(
          this.vulnerabilities, 
          this.auditSummary, 
          mergedOptions.outputFile, 
          format
        );
      }
      
      return this.auditSummary;
    } catch (error) {
      console.error('Error during security audit:', error);
      return {
        totalFiles: 0,
        totalVulnerabilities: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        bySeverity: {
          'critical': 0,
          'high': 0,
          'medium': 0,
          'low': 0,
          'info': 0,
          'warning': 0,
          'error': 0
        },
        byCategory: {},
        byLanguage: {
          'javascript': 0,
          'python': 0,
          'java': 0,
          'csharp': 0
        },
        topVulnerableFiles: [],
        topCategories: [],
        recommendations: []
      };
    }
  }
  
  /**
   * Generate a security audit report
   */
  public generateReport(): string {
    switch (this.options.outputFormat) {
      case 'json':
        return this.generateJsonReport();
      case 'html':
        return this.generateHtmlReport();
      case 'md':
        return this.generateMarkdownReport();
      case 'text':
      default:
        return this.generateTextReport();
    }
  }
  
  /**
   * Save the security audit report to a file
   */
  private saveReport(
    vulnerabilities: Vulnerability[], 
    summary: AuditSummary, 
    outputFile: string,
    format: 'json' | 'html' | 'markdown' | 'text'
  ): void {
    try {
      let content = '';
      
      switch (format) {
        case 'json':
          content = this.generateJsonReport();
          break;
        case 'html':
          content = this.generateHtmlReport();
          break;
        case 'markdown':
          content = this.generateMarkdownReport();
          break;
        case 'text':
        default:
          content = this.generateTextReport();
          break;
      }
      
      const fs = require('fs');
      const path = require('path');
      
      // Create directory if it doesn't exist
      const dir = path.dirname(outputFile);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      fs.writeFileSync(outputFile, content, 'utf8');
      console.log(`Report saved to ${outputFile}`);
    } catch (error) {
      console.error(`Error saving report: ${error}`);
    }
  }
  
  /**
   * Process vulnerabilities to update audit summary
   */
  private processVulnerabilities(vulnerabilities: Vulnerability[]): void {
    for (const vuln of vulnerabilities) {
      // Count by severity
      this.auditSummary.bySeverity[vuln.severity]++;
      
      // Update severity counts
      switch (vuln.severity) {
        case 'critical':
          this.auditSummary.criticalCount++;
          break;
        case 'high':
          this.auditSummary.highCount++;
          break;
        case 'medium':
          this.auditSummary.mediumCount++;
          break;
        case 'low':
          this.auditSummary.lowCount++;
          break;
        case 'info':
        case 'warning':
        case 'error':
          this.auditSummary.infoCount++;
          break;
      }
      
      // Count by category (derived from rule ID)
      const category = this.getCategoryFromRuleId(vuln.ruleId);
      this.auditSummary.byCategory[category] = (this.auditSummary.byCategory[category] || 0) + 1;
      
      // Count by language (derived from file extension or rule ID)
      const language = this.getLanguageFromFile(vuln.file);
      if (language) {
        this.auditSummary.byLanguage[language]++;
      }
      
      // Track vulnerable files
      this.trackVulnerableFile(vuln.file);
    }
    
    // Update total count
    this.auditSummary.totalVulnerabilities = vulnerabilities.length;
  }
  
  /**
   * Get vulnerability category from rule ID
   */
  private getCategoryFromRuleId(ruleId: string): string {
    // Extract category from rule ID format: language-category-number
    const parts = ruleId.split('-');
    if (parts.length >= 2) {
      // Handle special cases
      if (parts[0] === 'dep') return 'dependency';
      if (parts[0] === 'dynamic') return 'dynamic-analysis';
      if (parts[0] === 'taint') return 'taint-analysis';
      
      // Default to the second part for normal rule IDs
      return parts[1];
    }
    return 'other';
  }
  
  /**
   * Determine language from file extension
   */
  private getLanguageFromFile(filePath: string): SupportedLanguage | null {
    if (!filePath) return null;
    
    const ext = path.extname(filePath).toLowerCase();
    switch (ext) {
      case '.js':
      case '.ts':
      case '.jsx':
      case '.tsx':
        return 'javascript';
      case '.py':
        return 'python';
      case '.java':
        return 'java';
      case '.cs':
        return 'csharp';
      default:
        // Try to infer from rule ID prefix if available
        for (const vuln of this.vulnerabilities) {
          if (vuln.file === filePath && vuln.ruleId) {
            const prefix = vuln.ruleId.split('-')[0];
            if (prefix === 'js') return 'javascript';
            if (prefix === 'py') return 'python';
            if (prefix === 'java') return 'java';
            if (prefix === 'cs') return 'csharp';
          }
        }
        return null;
    }
  }
  
  /**
   * Track files with vulnerabilities
   */
  private trackVulnerableFile(filePath: string): void {
    if (!filePath) return;
    
    const existingFile = this.auditSummary.topVulnerableFiles.find(f => f.file === filePath);
    if (existingFile) {
      existingFile.count++;
    } else {
      this.auditSummary.topVulnerableFiles.push({ file: filePath, count: 1 });
    }
    
    // Sort by count in descending order, keeping only top 10
    this.auditSummary.topVulnerableFiles.sort((a, b) => b.count - a.count);
    if (this.auditSummary.topVulnerableFiles.length > 10) {
      this.auditSummary.topVulnerableFiles = this.auditSummary.topVulnerableFiles.slice(0, 10);
    }
  }
  
  /**
   * Perform dynamic analysis on codebase
   */
  private async performDynamicAnalysis(directory: string): Promise<Vulnerability[]> {
    const dynamicVulnerabilities: Vulnerability[] = [];
    
    try {
      // Find all relevant code files
      const files = this.findCodeFiles(directory);
      
      // Analyze each file
      for (const file of files) {
        const language = this.getLanguageFromFile(file);
        if (!language) continue;
        
        // Read file content
        const content = fs.readFileSync(file, 'utf8');
        
        // Run dynamic analysis
        const fileVulnerabilities = await this.runtimeAnalyzer.analyzeProgram(
          content,
          language,
          this.getStaticVulnerabilitiesForFile(file)
        );
        
        dynamicVulnerabilities.push(...fileVulnerabilities);
      }
    } catch (error) {
      console.error('Error during dynamic analysis:', error);
    }
    
    return dynamicVulnerabilities;
  }
  
  /**
   * Check dependencies for vulnerabilities
   */
  private async checkDependencies(directory: string): Promise<Vulnerability[]> {
    const dependencyVulnerabilities: Vulnerability[] = [];
    
    try {
      // Find dependency files
      const packageJsons = this.findFiles(directory, 'package.json');
      const requirementsTxts = this.findFiles(directory, 'requirements.txt');
      const pomXmls = this.findFiles(directory, 'pom.xml');
      const csprojFiles = this.findFiles(directory, '*.csproj');
      
      // Check each dependency file
      for (const file of packageJsons) {
        const vulns = this.dependencyChecker.check(file, 'javascript');
        dependencyVulnerabilities.push(...vulns);
      }
      
      for (const file of requirementsTxts) {
        const vulns = this.dependencyChecker.check(file, 'python');
        dependencyVulnerabilities.push(...vulns);
      }
      
      for (const file of pomXmls) {
        const vulns = this.dependencyChecker.check(file, 'java');
        dependencyVulnerabilities.push(...vulns);
      }
      
      for (const file of csprojFiles) {
        const vulns = this.dependencyChecker.check(file, 'csharp');
        dependencyVulnerabilities.push(...vulns);
      }
    } catch (error) {
      console.error('Error checking dependencies:', error);
    }
    
    return dependencyVulnerabilities;
  }
  
  /**
   * Get static vulnerabilities for a specific file
   */
  private getStaticVulnerabilitiesForFile(filePath: string): Vulnerability[] {
    return this.vulnerabilities.filter(v => v.file === filePath);
  }
  
  /**
   * Find all relevant code files in a directory
   */
  private findCodeFiles(directory: string): string[] {
    // JavaScript/TypeScript
    const jsFiles = this.findFiles(directory, '*.js', '*.ts', '*.jsx', '*.tsx');
    
    // Python
    const pyFiles = this.findFiles(directory, '*.py');
    
    // Java
    const javaFiles = this.findFiles(directory, '*.java');
    
    // C#
    const csFiles = this.findFiles(directory, '*.cs');
    
    return [...jsFiles, ...pyFiles, ...javaFiles, ...csFiles];
  }
  
  /**
   * Find files with specific patterns
   */
  private findFiles(directory: string, ...patterns: string[]): string[] {
    const results: string[] = [];
    
    // Simple implementation - in a real scanner we'd use glob patterns
    const processDir = (dir: string) => {
      if (this.shouldIgnoreDirectory(dir)) return;
      
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          processDir(fullPath);
        } else if (entry.isFile()) {
          // Check if file matches any pattern
          for (const pattern of patterns) {
            if (this.matchesPattern(entry.name, pattern)) {
              if (this.isFileSizeAcceptable(fullPath)) {
                results.push(fullPath);
              }
              break;
            }
          }
        }
      }
    };
    
    processDir(directory);
    return results;
  }
  
  /**
   * Check if a directory should be ignored
   */
  private shouldIgnoreDirectory(dirPath: string): boolean {
    const dirName = path.basename(dirPath);
    return this.options.ignorePatterns?.some(pattern => 
      dirName === pattern || dirPath.includes(`/${pattern}/`) || dirPath.includes(`\\${pattern}\\`)
    ) || false;
  }
  
  /**
   * Check if a filename matches a pattern
   */
  private matchesPattern(filename: string, pattern: string): boolean {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*');
    
    const regex = new RegExp(`^${regexPattern}$`, 'i');
    return regex.test(filename);
  }
  
  /**
   * Check if file size is within acceptable limits
   */
  private isFileSizeAcceptable(filePath: string): boolean {
    if (!this.options.maxFileSizeKb) return true;
    
    const stats = fs.statSync(filePath);
    const fileSizeKb = stats.size / 1024;
    return fileSizeKb <= this.options.maxFileSizeKb;
  }
  
  /**
   * Filter vulnerabilities by severity threshold
   */
  private filterBySeverity(vulnerabilities: Vulnerability[], threshold: Severity): Vulnerability[] {
    const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'warning', 'error', 'info'];
    const thresholdIndex = severityOrder.indexOf(threshold);
    
    if (thresholdIndex === -1) {
      return vulnerabilities;
    }
    
    return vulnerabilities.filter(vuln => {
      const vulnSeverityIndex = severityOrder.indexOf(vuln.severity);
      return vulnSeverityIndex <= thresholdIndex;
    });
  }
  
  /**
   * Generate a summary of vulnerabilities
   */
  private generateSummary(vulnerabilities: Vulnerability[]): AuditSummary {
    const summary: AuditSummary = {
      totalFiles: 0,
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      bySeverity: {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0,
        'warning': 0,
        'error': 0
      },
      byCategory: {},
      byLanguage: {
        'javascript': 0,
        'python': 0,
        'java': 0,
        'csharp': 0
      },
      topVulnerableFiles: [],
      topCategories: [],
      recommendations: []
    };

    // Count unique files
    const uniqueFiles = new Set(vulnerabilities.map(v => v.file));
    summary.totalFiles = uniqueFiles.size;

    // Count by severity
    for (const vuln of vulnerabilities) {
      summary.bySeverity[vuln.severity]++;
      
      switch (vuln.severity) {
        case 'critical':
          summary.criticalCount++;
          break;
        case 'high':
          summary.highCount++;
          break;
        case 'medium':
          summary.mediumCount++;
          break;
        case 'low':
          summary.lowCount++;
          break;
        case 'info':
          summary.infoCount++;
          break;
      }
      
      // Count by category
      const category = this.getCategoryFromRuleId(vuln.ruleId);
      if (!summary.byCategory[category]) {
        summary.byCategory[category] = 0;
      }
      summary.byCategory[category]++;
      
      // Count by language
      const language = this.getLanguageFromFile(vuln.file);
      if (language) {
        summary.byLanguage[language]++;
      }
      
      // Track vulnerable files
      this.trackVulnerableFile(vuln.file);
    }
    
    // Generate top vulnerable files
    const fileCountMap: Record<string, number> = {};
    for (const vuln of vulnerabilities) {
      if (!fileCountMap[vuln.file]) {
        fileCountMap[vuln.file] = 0;
      }
      fileCountMap[vuln.file]++;
    }
    
    summary.topVulnerableFiles = Object.entries(fileCountMap)
      .map(([file, count]) => ({ file, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    
    // Generate top categories
    summary.topCategories = Object.entries(summary.byCategory)
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
    
    return summary;
  }
  
  /**
   * Generate recommendations based on vulnerabilities and summary
   */
  private generateRecommendations(): string[] {
    const recommendations: string[] = [];
    
    // Add general recommendations
    if (this.auditSummary.criticalCount > 0) {
      recommendations.push('Address all critical vulnerabilities immediately as they pose significant security risks.');
    }
    
    if (this.auditSummary.highCount > 0) {
      recommendations.push('Prioritize fixing high severity issues, which could lead to system compromise.');
    }
    
    // Add recommendations based on vulnerability categories
    const categories = Object.keys(this.auditSummary.byCategory);
    
    if (categories.includes('injection')) {
      recommendations.push('Validate and sanitize all user inputs to prevent injection attacks.');
    }
    
    if (categories.includes('xss')) {
      recommendations.push('Implement Content Security Policy (CSP) and output encoding to mitigate XSS vulnerabilities.');
    }
    
    if (categories.includes('authentication')) {
      recommendations.push('Review authentication mechanisms and implement multi-factor authentication where appropriate.');
    }
    
    if (categories.includes('authorization')) {
      recommendations.push('Ensure proper access controls are in place and follow the principle of least privilege.');
    }
    
    if (categories.includes('crypto')) {
      recommendations.push('Review and update cryptographic implementations to use modern, secure algorithms and practices.');
    }
    
    if (categories.includes('dependency')) {
      recommendations.push('Regularly update dependencies and implement a vulnerability management process.');
    }
    
    // Add recommendation for most vulnerable file
    if (this.auditSummary.topVulnerableFiles.length > 0) {
      const mostVulnerableFile = this.auditSummary.topVulnerableFiles[0];
      recommendations.push(`Prioritize refactoring ${mostVulnerableFile.file} as it contains ${mostVulnerableFile.count} vulnerabilities.`);
    }
    
    return recommendations;
  }
  
  /**
   * Generate a JSON report of vulnerabilities and summary
   */
  private generateJsonReport(): string {
    const report = {
      vulnerabilities: this.vulnerabilities,
      summary: this.auditSummary,
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    };
    
    return JSON.stringify(report, null, 2);
  }
  
  /**
   * Generate an HTML report of vulnerabilities and summary
   */
  private generateHtmlReport(): string {
    let html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Security Audit Report</title>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }
        h1, h2, h3 { color: #0066cc; }
        .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .severity-critical { color: #7b0000; background-color: #ffdddd; }
        .severity-high { color: #cc0000; background-color: #ffe0e0; }
        .severity-medium { color: #ff6600; background-color: #fff1e0; }
        .severity-low { color: #ffcc00; background-color: #fffbe0; }
        .severity-info { color: #0066cc; background-color: #e0f0ff; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .recommendations { background-color: #e6f7ff; padding: 15px; border-radius: 5px; }
      </style>
    </head>
    <body>
      <h1>Security Audit Report</h1>
      
      <div class="summary">
        <h2>Summary</h2>
        <p>Total Files Scanned: ${this.auditSummary.totalFiles}</p>
        <p>Total Vulnerabilities: ${this.auditSummary.totalVulnerabilities}</p>
        <p>Critical: ${this.auditSummary.criticalCount}</p>
        <p>High: ${this.auditSummary.highCount}</p>
        <p>Medium: ${this.auditSummary.mediumCount}</p>
        <p>Low: ${this.auditSummary.lowCount}</p>
        <p>Info: ${this.auditSummary.infoCount}</p>
      </div>
      
      <h2>Vulnerabilities by Category</h2>
      <table>
        <tr>
          <th>Category</th>
          <th>Count</th>
        </tr>
    `;
    
    // Add category rows
    for (const [category, count] of Object.entries(this.auditSummary.byCategory)) {
      html += `
        <tr>
          <td>${category}</td>
          <td>${count}</td>
        </tr>
      `;
    }
    
    html += `
      </table>
      
      <h2>Top Vulnerable Files</h2>
      <table>
        <tr>
          <th>File</th>
          <th>Vulnerabilities</th>
        </tr>
    `;
    
    // Add file rows
    for (const { file, count } of this.auditSummary.topVulnerableFiles) {
      html += `
        <tr>
          <td>${file}</td>
          <td>${count}</td>
        </tr>
      `;
    }
    
    html += `
      </table>
      
      <h2>Vulnerabilities</h2>
      <table>
        <tr>
          <th>Rule</th>
          <th>Severity</th>
          <th>File</th>
          <th>Line</th>
          <th>Message</th>
        </tr>
    `;
    
    // Add vulnerability rows
    for (const vuln of this.vulnerabilities) {
      html += `
        <tr class="severity-${vuln.severity}">
          <td>${vuln.ruleId}</td>
          <td>${vuln.severity}</td>
          <td>${vuln.file}</td>
          <td>${vuln.line}</td>
          <td>${vuln.message}</td>
        </tr>
      `;
    }
    
    html += `
      </table>
      
      <div class="recommendations">
        <h2>Recommendations</h2>
        <ul>
    `;
    
    // Add recommendations
    for (const recommendation of this.auditSummary.recommendations) {
      html += `<li>${recommendation}</li>`;
    }
    
    html += `
        </ul>
      </div>
    </body>
    </html>
    `;
    
    return html;
  }
  
  /**
   * Generate a Markdown report of vulnerabilities and summary
   */
  private generateMarkdownReport(): string {
    let markdown = `# Security Audit Report

## Summary
- Total Files Scanned: ${this.auditSummary.totalFiles}
- Total Vulnerabilities: ${this.auditSummary.totalVulnerabilities}
- Critical: ${this.auditSummary.criticalCount}
- High: ${this.auditSummary.highCount}
- Medium: ${this.auditSummary.mediumCount}
- Low: ${this.auditSummary.lowCount}
- Info: ${this.auditSummary.infoCount}

## Vulnerabilities by Category
| Category | Count |
|----------|-------|
`;
    
    // Add category rows
    for (const [category, count] of Object.entries(this.auditSummary.byCategory)) {
      markdown += `| ${category} | ${count} |\n`;
    }
    
    markdown += `
## Top Vulnerable Files
| File | Vulnerabilities |
|------|-----------------|
`;
    
    // Add file rows
    for (const { file, count } of this.auditSummary.topVulnerableFiles) {
      markdown += `| ${file} | ${count} |\n`;
    }
    
    markdown += `
## Vulnerabilities
| Rule | Severity | File | Line | Message |
|------|----------|------|------|---------|
`;
    
    // Add vulnerability rows
    for (const vuln of this.vulnerabilities) {
      markdown += `| ${vuln.ruleId} | ${vuln.severity} | ${vuln.file} | ${vuln.line} | ${vuln.message} |\n`;
    }
    
    markdown += `
## Recommendations
`;
    
    // Add recommendations
    for (const recommendation of this.auditSummary.recommendations) {
      markdown += `- ${recommendation}\n`;
    }
    
    return markdown;
  }
  
  /**
   * Generate a plain text report of vulnerabilities and summary
   */
  private generateTextReport(): string {
    let text = `SECURITY AUDIT REPORT

SUMMARY
-------
Total Files Scanned: ${this.auditSummary.totalFiles}
Total Vulnerabilities: ${this.auditSummary.totalVulnerabilities}
Critical: ${this.auditSummary.criticalCount}
High: ${this.auditSummary.highCount}
Medium: ${this.auditSummary.mediumCount}
Low: ${this.auditSummary.lowCount}
Info: ${this.auditSummary.infoCount}

VULNERABILITIES BY CATEGORY
---------------------------
`;
    
    // Add category rows
    for (const [category, count] of Object.entries(this.auditSummary.byCategory)) {
      text += `${category}: ${count}\n`;
    }
    
    text += `
TOP VULNERABLE FILES
-------------------
`;
    
    // Add file rows
    for (const { file, count } of this.auditSummary.topVulnerableFiles) {
      text += `${file}: ${count} vulnerabilities\n`;
    }
    
    text += `
VULNERABILITIES
--------------
`;
    
    // Add vulnerability rows
    for (const vuln of this.vulnerabilities) {
      text += `[${vuln.severity}] ${vuln.ruleId}: ${vuln.message}
  File: ${vuln.file}
  Line: ${vuln.line}
  
`;
    }
    
    text += `
RECOMMENDATIONS
-------------
`;
    
    // Add recommendations
    for (const recommendation of this.auditSummary.recommendations) {
      text += `- ${recommendation}\n`;
    }
    
    return text;
  }
}

/**
 * Save the security audit report to a file
 */
export async function saveReport(
  vulnerabilities: Vulnerability[], 
  summary: AuditSummary, 
  outputFile: string,
  format: 'json' | 'html' | 'markdown' | 'text' | 'md'
): Promise<void> {
  try {
    let content = '';
    
    // Convert summary and vulnerabilities to JSON
    const reportData = {
      summary,
      vulnerabilities
    };
    
    switch (format) {
      case 'json':
        content = JSON.stringify(reportData, null, 2);
        break;
      case 'html':
        content = `<!DOCTYPE html>
<html>
<head>
  <title>Security Audit Report</title>
  <style>
    body { font-family: Arial, sans-serif; }
    .critical { color: darkred; }
    .high { color: red; }
    .medium { color: orange; }
    .low { color: green; }
    .info { color: blue; }
  </style>
</head>
<body>
  <h1>Security Audit Report</h1>
  <pre>${JSON.stringify(reportData, null, 2)}</pre>
</body>
</html>`;
        break;
      case 'markdown':
      case 'md':
        content = `# Security Audit Report\n\n## Summary\n\n${JSON.stringify(summary, null, 2)}\n\n## Vulnerabilities\n\n${JSON.stringify(vulnerabilities, null, 2)}`;
        break;
      case 'text':
      default:
        content = `SECURITY AUDIT REPORT\n\nSUMMARY:\n${JSON.stringify(summary, null, 2)}\n\nVULNERABILITIES:\n${JSON.stringify(vulnerabilities, null, 2)}`;
        break;
    }
    
    // Create directory if it doesn't exist
    const dir = path.dirname(outputFile);
    if (!fs.existsSync(dir)) {
      await fs.promises.mkdir(dir, { recursive: true });
    }
    
    await fs.promises.writeFile(outputFile, content, 'utf8');
    console.log(`Report saved to ${outputFile}`);
  } catch (error) {
    console.error(`Error saving report: ${error}`);
  }
} 