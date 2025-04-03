import fs from 'fs';
import path from 'path';
import { Scanner } from '../src/scanner';
import { ScanOptions, SupportedLanguage } from '../src/interfaces';

describe('Vulnerability Scanner', () => {
  let scanner: Scanner;
  let vulnerableCode: string;

  beforeAll(() => {
    scanner = new Scanner();
    vulnerableCode = fs.readFileSync(path.join(__dirname, 'samples/vulnerable.js'), 'utf8');
  });

  test('should initialize properly', () => {
    expect(scanner).toBeDefined();
  });

  test('should scan JavaScript code and detect vulnerabilities', () => {
    const result = scanner.scan(vulnerableCode, 'javascript' as SupportedLanguage);
    
    // Verify that the scanner works and finds vulnerabilities
    expect(result).toBeDefined();
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    expect(result.summary!.total).toBeGreaterThan(0);
    expect(result.summary!.total).toBe(result.vulnerabilities.length);
  });

  test('should detect SQL Injection vulnerabilities', () => {
    const code = `
      function getUserData(userId) {
        const query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return db.query(query);
      }
    `;
    const result = scanner.scan(code, 'javascript' as SupportedLanguage);
    
    const sqlInjectionVulns = result.vulnerabilities.filter(
      v => v.ruleId === 'js-sqli-001'
    );

    expect(sqlInjectionVulns.length).toBeGreaterThan(0);
    expect(sqlInjectionVulns[0].severity).toBe('critical');
  });

  test('should detect XSS vulnerabilities', () => {
    const code = `
      function displayUserComment(comment) {
        document.getElementById('comments').innerHTML = comment;
      }
    `;
    const result = scanner.scan(code, 'javascript' as SupportedLanguage);
    
    const xssVulns = result.vulnerabilities.filter(
      v => v.ruleId === 'js-xss-001'
    );

    expect(xssVulns.length).toBeGreaterThan(0);
    expect(xssVulns[0].severity).toBe('critical');
  });

  test('should detect command injection vulnerabilities', () => {
    const code = `
      function executeCommand(userInput) {
        const { exec } = require('child_process');
        exec('ls ' + userInput);
      }
    `;
    const result = scanner.scan(code, 'javascript' as SupportedLanguage);
    
    const cmdInjectionVulns = result.vulnerabilities.filter(
      v => v.ruleId === 'js-cmd-001'
    );

    expect(cmdInjectionVulns.length).toBeGreaterThan(0);
    expect(cmdInjectionVulns[0].severity).toBe('critical');
  });

  test('should detect insecure JWT validation', () => {
    const code = `
      function verifyToken(token) {
        const jwt = require('jsonwebtoken');
        return jwt.verify(token, secretKey);
      }
    `;
    const result = scanner.scan(code, 'javascript' as SupportedLanguage);
    
    const jwtVulns = result.vulnerabilities.filter(
      v => v.ruleId === 'js-jwt-001'
    );

    expect(jwtVulns.length).toBeGreaterThan(0);
  });

  test('should detect path traversal vulnerabilities', () => {
    const code = `
      function readUserFile(fileName) {
        const fs = require('fs');
        return fs.readFileSync('./user_files/' + req.params.fileName);
      }
    `;
    const result = scanner.scan(code, 'javascript' as SupportedLanguage);
    
    const pathVulns = result.vulnerabilities.filter(
      v => v.ruleId === 'js-path-001'
    );

    expect(pathVulns.length).toBeGreaterThan(0);
    expect(pathVulns[0].severity).toBe('critical');
  });

  test('should detect weak cryptography usage', () => {
    const code = `
      function hashPassword(password) {
        const crypto = require('crypto');
        return crypto.createHash('md5').update(password).digest('hex');
      }
    `;
    const result = scanner.scan(code, 'javascript' as SupportedLanguage);
    
    const cryptoVulns = result.vulnerabilities.filter(
      v => v.ruleId === 'js-crypto-001'
    );

    expect(cryptoVulns.length).toBeGreaterThan(0);
    expect(cryptoVulns[0].severity).toBe('high');
  });

  test('should include suggestions for fixing vulnerabilities', () => {
    const result = scanner.scan(vulnerableCode, 'javascript' as SupportedLanguage);
    
    // Check that fixes are provided
    const vulnsWithFixes = result.vulnerabilities.filter(v => v.fix);
    expect(vulnsWithFixes.length).toBeGreaterThan(0);
    
    // Each fix should contain description, replacement, and range information
    for (const vuln of vulnsWithFixes) {
      expect(vuln.fix?.description).toBeDefined();
      expect(vuln.fix?.replacement).toBeDefined();
      expect(vuln.fix?.range).toBeDefined();
    }
  });

  test('should correctly calculate summary statistics', () => {
    const result = scanner.scan(vulnerableCode, 'javascript' as SupportedLanguage);
    
    // Check that summary counts match the actual vulnerability counts
    const infoCount = result.vulnerabilities.filter(v => v.severity === 'info').length;
    const warningCount = result.vulnerabilities.filter(v => v.severity === 'warning').length;
    const errorCount = result.vulnerabilities.filter(v => v.severity === 'error').length;
    const criticalCount = result.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = result.vulnerabilities.filter(v => v.severity === 'high').length;
    
    expect(result.summary!.info).toBe(infoCount);
    expect(result.summary!.warning).toBe(warningCount);
    expect(result.summary!.error).toBe(errorCount);
    expect(result.summary!.critical).toBe(criticalCount);
    expect(result.summary!.high).toBe(highCount);
    expect(result.summary!.total).toBe(infoCount + warningCount + errorCount + criticalCount + highCount);
  });

  test('should detect Python SQL injection vulnerabilities', () => {
    const code = `
      def get_user(user_id):
          query = "SELECT * FROM users WHERE id = %s" % user_id
          cursor.execute(query)
          return cursor.fetchall()
    `;
    const result = scanner.scan(code, 'python' as SupportedLanguage);
    
    const sqlInjectionVulns = result.vulnerabilities.filter(
      v => v.ruleId === 'py-sqli-001'
    );

    expect(sqlInjectionVulns.length).toBeGreaterThan(0);
    expect(sqlInjectionVulns[0].severity).toBe('critical');
  });

  test('should detect Java SQL injection vulnerabilities', () => {
    const code = `
      public List<User> getUser(String userId) {
          String query = "SELECT * FROM users WHERE id = '" + userId + "'";
          return jdbcTemplate.query(query, new UserRowMapper());
      }
    `;
    const result = scanner.scan(code, 'java' as SupportedLanguage);
    
    const sqlInjectionVulns = result.vulnerabilities.filter(
      v => v.ruleId === 'java-sqli-001'
    );

    expect(sqlInjectionVulns.length).toBeGreaterThan(0);
    expect(sqlInjectionVulns[0].severity).toBe('critical');
  });

  test('should detect C# SQL injection vulnerabilities', () => {
    const code = `
      public List<User> GetUsers(string userId) {
          string query = "SELECT * FROM Users WHERE Id = '" + userId + "'";
          SqlCommand command = new SqlCommand(query, connection);
          SqlDataReader reader = command.ExecuteReader();
      }
    `;
    const result = scanner.scan(code, 'csharp' as SupportedLanguage);
    
    const sqlInjectionVulns = result.vulnerabilities.filter(
      v => v.ruleId === 'cs-sqli-001'
    );

    expect(sqlInjectionVulns.length).toBeGreaterThan(0);
    expect(sqlInjectionVulns[0].severity).toBe('critical');
  });

  test('should respect ignorePatterns in options', () => {
    const code = `
      // scan-ignore-file
      function getUserData(userId) {
        const query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return db.query(query);
      }
    `;
    const scanner = new Scanner();
    const result = scanner.scan(code, 'javascript' as SupportedLanguage);
    
    expect(result.vulnerabilities.length).toBe(0);
  });

  test('should respect rule filtering', () => {
    const scanOptions: ScanOptions = {
      rules: ['js-xss-001'],
      ignorePatterns: []
    };
    
    const scanner = new Scanner(scanOptions);
    const result = scanner.scan(vulnerableCode, 'javascript' as SupportedLanguage);
    
    // Should only detect XSS vulnerabilities
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    result.vulnerabilities.forEach(vuln => {
      expect(vuln.ruleId).toBe('js-xss-001');
    });
  });

  test('should respect rule exclusion', () => {
    const scanOptions: ScanOptions = {
      excludeRules: ['js-xss-001'],
      ignorePatterns: []
    };
    
    const scanner = new Scanner(scanOptions);
    const result = scanner.scan(vulnerableCode, 'javascript' as SupportedLanguage);
    
    // Should not detect any XSS vulnerabilities
    const xssVulns = result.vulnerabilities.filter(v => v.ruleId === 'js-xss-001');
    expect(xssVulns.length).toBe(0);
    
    // But should detect other types
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
  });
}); 