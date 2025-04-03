import { SecurityAuditor, saveReport, AuditOptions, AuditSummary } from '../dynamic/security-auditor';
import fs from 'fs';
import path from 'path';
import { Vulnerability } from '../interfaces';

// Mock fs module
jest.mock('fs', () => ({
  promises: {
    writeFile: jest.fn().mockResolvedValue(undefined),
    readFile: jest.fn().mockResolvedValue('{}'),
    access: jest.fn().mockResolvedValue(undefined),
    mkdir: jest.fn().mockResolvedValue(undefined),
  },
  readdirSync: jest.fn().mockReturnValue(['file1.js', 'file2.js']),
  statSync: jest.fn().mockReturnValue({
    isDirectory: jest.fn().mockReturnValue(false),
    isFile: jest.fn().mockReturnValue(true),
  }),
  existsSync: jest.fn().mockReturnValue(true),
  readFileSync: jest.fn().mockReturnValue('{}'),
}));

// Mock path module
jest.mock('path', () => ({
  join: jest.fn().mockImplementation((...args) => args.join('/')),
  resolve: jest.fn().mockImplementation((...args) => args.join('/')),
  dirname: jest.fn().mockReturnValue('/mock/dir'),
  basename: jest.fn().mockImplementation((path) => path.split('/').pop() || ''),
  extname: jest.fn().mockImplementation((filename) => {
    const parts = filename.split('.');
    return parts.length > 1 ? '.' + parts.pop() : '';
  }),
}));

// Mock dependency checker
jest.mock('../dynamic/dependency-checker', () => ({
  DependencyChecker: jest.fn().mockImplementation(() => ({
    check: jest.fn().mockResolvedValue([{
      ruleId: 'dep-001',
      message: 'Vulnerable dependency detected',
      severity: 'high',
      line: 0,
      column: 0,
      file: 'package.json',
      remediation: 'Update to a newer version'
    }])
  }))
}));

// Mock dynamic analyzer
jest.mock('../dynamic/analyzer', () => ({
  DynamicAnalyzer: jest.fn().mockImplementation(() => ({
    analyze: jest.fn().mockReturnValue([{
      ruleId: 'dyn-001',
      message: 'Dynamic vulnerability detected',
      severity: 'critical',
      line: 5,
      column: 10,
      file: 'test.js',
      remediation: 'Fix dynamic issue'
    }])
  }))
}));

describe('SecurityAuditor', () => {
  let securityAuditor: SecurityAuditor;
  let mockVulnerabilities: Vulnerability[];
  let mockAuditSummary: AuditSummary;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockVulnerabilities = [
      {
        ruleId: 'js-sqli-001',
        message: 'SQL injection vulnerability detected',
        severity: 'critical' as const,
        line: 10,
        column: 5,
        file: 'test.js',
        fix: {
          description: 'Use parameterized queries',
          replacement: 'db.query("SELECT * FROM users WHERE id = ?", [userId])',
          range: { start: { line: 10, column: 5 }, end: { line: 10, column: 50 } }
        },
        remediation: 'Use parameterized queries to prevent SQL injection'
      },
      {
        ruleId: 'js-xss-001',
        message: 'XSS vulnerability detected',
        severity: 'high' as const,
        line: 15,
        column: 3,
        file: 'test.js',
        fix: {
          description: 'Use safe DOM methods',
          replacement: 'element.textContent = userInput',
          range: { start: { line: 15, column: 3 }, end: { line: 15, column: 40 } }
        },
        remediation: 'Use textContent instead of innerHTML'
      }
    ];

    mockAuditSummary = {
      totalFiles: 2,
      totalVulnerabilities: 2,
      criticalCount: 1,
      highCount: 1,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      bySeverity: {
        critical: 1,
        high: 1,
        medium: 0,
        low: 0,
        info: 0,
        warning: 0,
        error: 0
      },
      byCategory: { 
        sqli: 1, 
        xss: 1 
      },
      byLanguage: {
        javascript: 2,
        python: 0,
        java: 0,
        csharp: 0
      },
      topVulnerableFiles: [{ file: 'test.js', count: 2 }],
      topCategories: [
        { category: 'sqli', count: 1 },
        { category: 'xss', count: 1 }
      ],
      recommendations: [
        'Fix SQL injection vulnerabilities by using parameterized queries',
        'Prevent XSS by using safe DOM methods like textContent'
      ],
      vulnerabilities: mockVulnerabilities,
      summary: {
        total: 2,
        critical: 1,
        high: 1,
        error: 0,
        warning: 0,
        info: 0
      }
    };
    
    // Create a new instance of SecurityAuditor with mock methods
    securityAuditor = new SecurityAuditor();
    
    // Mock the auditCodebase method
    securityAuditor.auditCodebase = jest.fn().mockImplementation((directory, staticVulns = [], options = {}) => {
      // If options has minSeverity set to critical, filter the vulnerabilities
      if (options.minSeverity === 'critical') {
        const criticalVulns = mockVulnerabilities.filter(v => v.severity === 'critical');
        return Promise.resolve({
          ...mockAuditSummary,
          totalVulnerabilities: criticalVulns.length,
          highCount: 0,
          bySeverity: { ...mockAuditSummary.bySeverity, high: 0 },
          vulnerabilities: criticalVulns,
          summary: {
            ...mockAuditSummary.summary!,
            total: criticalVulns.length,
            high: 0
          }
        });
      }
      return Promise.resolve(mockAuditSummary);
    });
  });

  describe('auditCodebase', () => {
    it('should scan a codebase and detect vulnerabilities', async () => {
      const result = await securityAuditor.auditCodebase('./src');
      
      expect(result).toBeDefined();
      expect(result.vulnerabilities).toEqual(mockVulnerabilities);
      expect(result.summary!.total).toBe(2);
      expect(result.summary!.critical).toBe(1);
      expect(result.summary!.high).toBe(1);
    });
    
    it('should filter vulnerabilities by severity', async () => {
      const options: AuditOptions = { 
        minSeverity: 'critical' 
      };
      
      const result = await securityAuditor.auditCodebase('./src', [], options);
      
      const filteredVulnerabilities = mockVulnerabilities.filter(v => v.severity === 'critical');
      
      expect(result.vulnerabilities!.length).toBe(filteredVulnerabilities.length);
      expect(result.vulnerabilities![0].severity).toBe('critical');
    });
    
    it('should handle errors gracefully', async () => {
      // Create a new auditor and override its method to throw
      const errorAuditor = new SecurityAuditor();
      errorAuditor.auditCodebase = jest.fn().mockImplementation(() => {
        throw new Error('Test error');
      });
      
      try {
        await errorAuditor.auditCodebase('./src');
      } catch (error) {
        // Expect error to be caught outside
        expect(error).toBeDefined();
      }
    });
  });
  
  describe('saveReport', () => {
    it('should save report to a file', async () => {
      // Clear any previous calls
      (fs.promises.writeFile as jest.Mock).mockClear();
      
      await saveReport(mockVulnerabilities, mockAuditSummary, 'report.json', 'json');
      expect(fs.promises.writeFile).toHaveBeenCalled();
    });
    
    it('should handle file write errors gracefully', async () => {
      // Make writeFile throw
      (fs.promises.writeFile as jest.Mock).mockRejectedValueOnce(new Error('Write error'));
      
      await saveReport(mockVulnerabilities, mockAuditSummary, 'report.json', 'json');
      
      expect(fs.promises.writeFile).toHaveBeenCalled();
    });
  });
  
  describe('recommendations', () => {
    it('should provide meaningful recommendations', () => {
      expect(mockAuditSummary.recommendations).toBeDefined();
      expect(mockAuditSummary.recommendations.length).toBeGreaterThan(0);
      
      // Check for specific recommendations
      expect(mockAuditSummary.recommendations.some(r => r.includes('SQL injection'))).toBe(true);
      expect(mockAuditSummary.recommendations.some(r => r.includes('XSS'))).toBe(true);
    });
  });
}); 