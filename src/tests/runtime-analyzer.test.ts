import * as fs from 'fs';
import * as path from 'path';
import { RuntimeAnalyzer } from '../dynamic/runtime-analyzer';
import { Vulnerability, SupportedLanguage } from '../interfaces';
import { TaintTracker } from '../dynamic/taint-tracker';
import { ExecutionContext } from '../dynamic/context';

// Mock dependencies
jest.mock('fs');
jest.mock('vm');
jest.mock('../dynamic/taint-tracker');
jest.mock('../dynamic/context', () => {
  return {
    ExecutionContext: jest.fn().mockImplementation(() => ({
      recordEvent: jest.fn(),
      log: jest.fn(),
      recordFileAccess: jest.fn(),
      recordNetworkRequest: jest.fn(),
      recordCommandExecution: jest.fn(),
      getVulnerabilities: jest.fn().mockReturnValue([{
        ruleId: 'dynamic-eval-001',
        message: 'Dynamic eval detected',
        severity: 'high' as const,
        line: 1,
        column: 1,
        file: 'test.js',
        remediation: 'Avoid using eval'
      }]),
      reset: jest.fn()
    }))
  };
});

jest.mock('../dynamic/taint-tracker', () => {
  return {
    TaintTracker: jest.fn().mockImplementation(() => ({
      instrumentCode: jest.fn().mockReturnValue('instrumented code'),
      checkSinks: jest.fn(),
      markTainted: jest.fn(),
      getVulnerabilities: jest.fn().mockReturnValue([{
        ruleId: 'taint-sql-001',
        message: 'Tainted SQL detected',
        severity: 'high' as const,
        line: 1,
        column: 1,
        file: 'test.js',
        remediation: 'Use parameterized queries'
      }]),
      reset: jest.fn()
    }))
  };
});

jest.mock('../dynamic/test-generator', () => {
  return {
    TestGenerator: jest.fn().mockImplementation(() => ({
      generateTests: jest.fn().mockReturnValue([
        { name: 'test1', input: 'malicious input' }
      ])
    }))
  };
});

// Mock vm module
jest.mock('vm', () => ({
  Script: jest.fn().mockImplementation(() => ({
    runInContext: jest.fn()
  })),
  createContext: jest.fn().mockReturnValue({})
}));

const VULNERABLE_JS_CODE = `
const express = require('express');
const app = express();
const fs = require('fs');
const cp = require('child_process');

app.get('/unsafe', (req, res) => {
  const userInput = req.query.input;
  
  // SQL Injection
  const query = "SELECT * FROM users WHERE name = '" + userInput + "'";
  
  // Command Injection
  cp.exec('ls ' + userInput, (err, stdout) => {
    console.log(stdout);
  });
  
  // Path Traversal
  fs.readFile('/var/data/' + userInput, (err, data) => {
    res.send(data);
  });
  
  // Unsafe eval
  eval('console.log("' + userInput + '")');
  
  res.send('Done');
});

app.listen(3000);
`;

describe('RuntimeAnalyzer', () => {
  let analyzer: RuntimeAnalyzer;
  
  beforeEach(() => {
    analyzer = new RuntimeAnalyzer();
  });
  
  describe('analyzeProgram', () => {
    it('should route to the correct language-specific analyzer', async () => {
      // Spy on language-specific methods
      const jsAnalyzeSpy = jest.spyOn(analyzer as any, 'analyzeJavaScript').mockResolvedValue([]);
      const pythonAnalyzeSpy = jest.spyOn(analyzer as any, 'analyzePython').mockResolvedValue([]);
      const javaAnalyzeSpy = jest.spyOn(analyzer as any, 'analyzeJava').mockResolvedValue([]);
      const csharpAnalyzeSpy = jest.spyOn(analyzer as any, 'analyzeCSharp').mockResolvedValue([]);
      
      // Test JavaScript
      await analyzer.analyzeProgram('console.log("test")', 'javascript', []);
      expect(jsAnalyzeSpy).toHaveBeenCalled();
      
      // Test Python
      await analyzer.analyzeProgram('print("test")', 'python', []);
      expect(pythonAnalyzeSpy).toHaveBeenCalled();
      
      // Test Java
      await analyzer.analyzeProgram('class Test { }', 'java', []);
      expect(javaAnalyzeSpy).toHaveBeenCalled();
      
      // Test C#
      await analyzer.analyzeProgram('class Test { }', 'csharp', []);
      expect(csharpAnalyzeSpy).toHaveBeenCalled();
      
      // Test unsupported language
      const result = await analyzer.analyzeProgram('test', 'unsupported' as SupportedLanguage, []);
      expect(result).toEqual([]);
    });
  });
  
  describe('analyzeJavaScript', () => {
    it('should analyze JavaScript code and detect vulnerabilities', async () => {
      const mockVulnerability = {
        ruleId: 'js-sqli-001',
        message: 'SQL Injection vulnerability',
        severity: 'high' as const,
        line: 3,
        column: 10,
        file: 'test.js',
        remediation: 'Use parameterized queries'
      };
      
      const result = await analyzer.analyzeJavaScript('vulnerable code', [mockVulnerability]);
      
      // Check that analysis returned vulnerabilities
      expect(result).toBeInstanceOf(Array);
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContainEqual(mockVulnerability);
    });
    
    it('should merge static vulnerabilities with dynamic findings', async () => {
      // Set up a static vulnerability
      const staticVuln: Vulnerability = {
        ruleId: 'static-sqli-001',
        message: 'Static SQL Injection',
        severity: 'high',
        line: 5,
        column: 10,
        file: 'test.js',
        remediation: 'Use parameterized queries'
      };
      
      // Dynamic vulnerability comes from mocked taint tracker
      const dynamicVuln: Vulnerability = {
        ruleId: 'taint-sql-001',
        message: 'Tainted SQL detected',
        severity: 'high',
        line: 1,
        column: 1,
        file: 'test.js',
        remediation: 'Use parameterized queries'
      };
      
      const result = await analyzer.analyzeJavaScript('var x = 1;', [staticVuln]);
      
      // Check that analysis merged both vulnerabilities
      expect(result).toBeInstanceOf(Array);
      expect(result.length).toBe(3); // static + tainted + context vulnerabilities
      expect(result).toContainEqual(staticVuln);
      expect(result).toContainEqual(dynamicVuln);
    });
    
    it('should handle syntax errors gracefully', async () => {
      // Test with invalid JavaScript code
      const result = await analyzer.analyzeJavaScript('function foo() { syntax error }', []);
      
      // Should still return an array even if analysis fails
      expect(result).toBeInstanceOf(Array);
    });
  });
  
  describe('createSandbox', () => {
    it('should create a sandbox with mocked globals', () => {
      // Access private method using type assertion
      const sandbox = (analyzer as any).createSandbox();
      
      // Check that sandbox contains expected objects
      expect(sandbox).toHaveProperty('console');
      expect(sandbox).toHaveProperty('require');
      expect(sandbox).toHaveProperty('process');
      expect(sandbox).toHaveProperty('setTimeout');
      expect(sandbox).toHaveProperty('Buffer');
      expect(sandbox).toHaveProperty('JSON');
      expect(sandbox).toHaveProperty('eval');
    });
    
    it('should monitor sandbox activities', () => {
      // Mock the execution context
      const recordEventMock = jest.fn();
      (ExecutionContext as jest.Mock).mockImplementation(() => ({
        recordEvent: recordEventMock,
        log: jest.fn()
      }));
      
      // Recreate RuntimeAnalyzer with mocked dependencies
      analyzer = new RuntimeAnalyzer();
      
      // Access private method and get sandbox
      const sandbox = (analyzer as any).createSandbox();
      
      // Trigger monitored methods
      sandbox.JSON.parse('{"test": true}');
      sandbox.console.log('test');
      
      // Check that events were recorded
      expect(recordEventMock).toHaveBeenCalled();
    });
  });
  
  describe('mock modules', () => {
    it('should provide mock implementations of common Node.js modules', () => {
      // Mock the execution context
      const recordEventMock = jest.fn();
      (ExecutionContext as jest.Mock).mockImplementation(() => ({
        recordEvent: recordEventMock,
        log: jest.fn()
      }));
      
      // Recreate RuntimeAnalyzer with mocked dependencies
      analyzer = new RuntimeAnalyzer();
      
      // Access private method and test mocked require
      const mockRequire = (analyzer as any).mockRequire.bind(analyzer);
      
      const fsMock = mockRequire('fs');
      const httpMock = mockRequire('http');
      const cpMock = mockRequire('child_process');
      const expressMock = mockRequire('express');
      
      // Check that modules were mocked and events recorded
      expect(fsMock).toBeDefined();
      expect(httpMock).toBeDefined();
      expect(cpMock).toBeDefined();
      expect(expressMock).toBeDefined();
      expect(recordEventMock).toHaveBeenCalledTimes(4);
    });
  });
  
  describe('non-JavaScript analysis', () => {
    it('should analyze Python code', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const pythonCode = `
print("Hello, world!")
user_input = input()
os.system("ls " + user_input)  # Command injection
      `;
      
      const result = await (analyzer as any).analyzePython(pythonCode, []);
      
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("Python analysis"));
      expect(result).toBeInstanceOf(Array);
      
      consoleSpy.mockRestore();
    });
    
    it('should analyze Java code', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const javaCode = `
class Test {
  public static void main(String[] args) {
    String userInput = args[0];
    Runtime.getRuntime().exec("ls " + userInput);  // Command injection
  }
}
      `;
      
      const result = await (analyzer as any).analyzeJava(javaCode, []);
      
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("Java analysis"));
      expect(result).toBeInstanceOf(Array);
      
      consoleSpy.mockRestore();
    });
    
    it('should analyze C# code', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const csharpCode = `
class Program {
  static void Main(string[] args) {
    string userInput = args[0];
    System.Diagnostics.Process.Start("cmd.exe", "/c dir " + userInput);  // Command injection
  }
}
      `;
      
      const result = await (analyzer as any).analyzeCSharp(csharpCode, []);
      
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("C# analysis"));
      expect(result).toBeInstanceOf(Array);
      
      consoleSpy.mockRestore();
    });
  });
}); 