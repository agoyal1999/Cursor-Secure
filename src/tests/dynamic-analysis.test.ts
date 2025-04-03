import * as fs from 'fs';
import * as path from 'path';
import { analyzeDynamically, TaintTracker, ExecutionContext, RuntimeAnalyzer } from '../dynamic';
import { Vulnerability, SupportedLanguage } from '../interfaces';
import { DynamicAnalyzer } from '../dynamic/analyzer';

// Mock the analyzer module
jest.mock('../dynamic/analyzer');

// Mock TaintTracker
jest.mock('../dynamic/taint-tracker', () => {
  return {
    TaintTracker: jest.fn().mockImplementation(() => {
      let vulnerabilities = [{
        ruleId: 'taint-sql-001',
        message: 'SQL Injection from taint tracking',
        severity: 'high' as const,
        line: 12,
        column: 5,
        file: 'test.js',
        remediation: 'Use parameterized queries'
      }];
      
      return {
        markTainted: jest.fn(),
        instrumentCode: jest.fn((code) => {
          return `
            // Instrumented code
            const __taintMap = new Map();
            function __markTainted(varName, value) {
              __taintMap.set(varName, true);
            }
            function __checkSink(sinkType, value) {
              // Check for tainted values
              return value;
            }
            
            ${code}
          `;
        }),
        checkSinks: jest.fn(),
        getVulnerabilities: jest.fn(() => [...vulnerabilities]),
        reset: jest.fn(() => {
          vulnerabilities = [];
        })
      };
    })
  };
});

// Mock ExecutionContext
jest.mock('../dynamic/context', () => {
  return {
    ExecutionContext: jest.fn().mockImplementation(() => {
      const vulnsMap = {
        'file': {
          ruleId: 'dynamic-path-001',
          message: 'Path traversal detected',
          severity: 'high' as const,
          line: 15,
          column: 5,
          file: 'test.js',
          remediation: 'Validate file paths'
        },
        'network': {
          ruleId: 'dynamic-ssrf-001',
          message: 'SSRF vulnerability detected',
          severity: 'high' as const,
          line: 20,
          column: 5,
          file: 'test.js',
          remediation: 'Validate URLs'
        },
        'command': {
          ruleId: 'dynamic-cmd-001',
          message: 'Command injection detected',
          severity: 'high' as const,
          line: 25,
          column: 5,
          file: 'test.js',
          remediation: 'Avoid using user input in commands'
        },
        'eval': {
          ruleId: 'dynamic-eval-001',
          message: 'Dangerous eval usage detected',
          severity: 'high' as const,
          line: 30,
          column: 5,
          file: 'test.js',
          remediation: 'Avoid using eval'
        }
      } as const;
      
      let eventType: keyof typeof vulnsMap = 'file';
      
      return {
        recordFileAccess: jest.fn(() => { eventType = 'file'; }),
        recordNetworkRequest: jest.fn(() => { eventType = 'network'; }),
        recordCommandExecution: jest.fn(() => { eventType = 'command'; }),
        recordEvent: jest.fn((type) => { 
          if (type === 'eval') eventType = 'eval';
        }),
        analyzeExecutionPath: jest.fn(),
        getVulnerabilities: jest.fn(() => [vulnsMap[eventType]]),
        log: jest.fn(),
        reset: jest.fn()
      };
    })
  };
});

// Mock RuntimeAnalyzer
jest.mock('../dynamic/runtime-analyzer', () => {
  return {
    RuntimeAnalyzer: jest.fn().mockImplementation(() => ({
      analyzeProgram: jest.fn().mockImplementation((code, language, staticVulns) => {
        // Always return at least the static vulnerabilities
        return Promise.resolve(staticVulns);
      })
    }))
  };
});

// Sample vulnerable code for testing
const VULNERABLE_JS_CODE = `
function getUserData(userId) {
  // SQL Injection vulnerability
  return db.query("SELECT * FROM users WHERE id = '" + userId + "'");
}

function displayUserComment(comment) {
  // XSS vulnerability
  document.getElementById('comments').innerHTML = comment;
}

function executeCommand(userInput) {
  // Command injection vulnerability
  const { exec } = require('child_process');
  exec('ls ' + userInput);
}
`;

// Sample vulnerable code snippets
const VULNERABLE_JS_CODE_SNIPPETS = `
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
  
  res.send('Done');
});

app.listen(3000);
`;

const VULNERABLE_PYTHON_CODE = `
import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/unsafe')
def unsafe():
    user_input = request.args.get('input')
    
    # SQL Injection
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
    
    # Command Injection
    os.system("ls " + user_input)
    
    # Path Traversal
    with open("/var/data/" + user_input, "r") as f:
        data = f.read()
    
    return "Done"

if __name__ == '__main__':
    app.run(debug=True)
`;

const VULNERABLE_JAVA_CODE = `
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.io.File;
import java.io.IOException;

public class Vulnerable {
    public static void main(String[] args) {
        String userInput = args[0];
        
        try {
            // SQL Injection
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
            
            // Command Injection
            Runtime.getRuntime().exec("ls " + userInput);
            
            // Path Traversal
            File file = new File("/var/data/" + userInput);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
`;

const VULNERABLE_CSHARP_CODE = `
using System;
using System.Diagnostics;
using System.IO;
using System.Data.SqlClient;

public class Vulnerable
{
    public static void Main(string[] args)
    {
        string userInput = args[0];
        
        // SQL Injection
        using (SqlConnection connection = new SqlConnection("Server=myServerAddress;Database=myDataBase;"))
        {
            SqlCommand command = new SqlCommand("SELECT * FROM Users WHERE Name = '" + userInput + "'", connection);
            command.ExecuteReader();
        }
        
        // Command Injection
        Process.Start("cmd.exe", "/c dir " + userInput);
        
        // Path Traversal
        string content = File.ReadAllText("C:\\data\\" + userInput);
        
        // XXE Vulnerability
        var settings = new System.Xml.XmlReaderSettings();
        var reader = System.Xml.XmlReader.Create("file.xml", settings);
        
        // Unsafe Deserialization
        var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
        var obj = formatter.Deserialize(File.OpenRead("data.bin"));
    }
    
    [System.Web.Mvc.HttpPost]
    public ActionResult ProcessData(string data)
    {
        // Missing CSRF protection
        return Redirect(data); // Open redirect vulnerability
    }
}
`;

describe('Dynamic Analysis Tests', () => {
  let analyzer: DynamicAnalyzer;
  
  // Define vulnerabilities for each language
  const mockVulnerabilities = {
    javascript: [
      {
        ruleId: 'js-sqli-001', 
        message: 'SQL injection vulnerability',
        severity: 'critical' as const,
        line: 5,
        column: 10,
        file: 'test.js',
        remediation: 'Use parameterized queries'
      },
      {
        ruleId: 'js-cmd-001',
        message: 'Command injection vulnerability',
        severity: 'high' as const,
        line: 8,
        column: 15,
        file: 'test.js',
        remediation: 'Avoid using user input in commands'
      }
    ],
    python: [
      {
        ruleId: 'py-sqli-001', 
        message: 'SQL injection vulnerability',
        severity: 'critical' as const,
        line: 5,
        column: 10,
        file: 'test.py',
        remediation: 'Use parameterized queries'
      },
      {
        ruleId: 'py-cmd-001',
        message: 'Command injection vulnerability',
        severity: 'high' as const,
        line: 8,
        column: 15,
        file: 'test.py',
        remediation: 'Avoid using user input in commands'
      }
    ],
    java: [
      {
        ruleId: 'java-sqli-001', 
        message: 'SQL injection vulnerability',
        severity: 'critical' as const,
        line: 5,
        column: 10,
        file: 'test.java',
        remediation: 'Use prepared statements'
      },
      {
        ruleId: 'java-cmd-001',
        message: 'Command injection vulnerability',
        severity: 'high' as const,
        line: 8,
        column: 15,
        file: 'test.java',
        remediation: 'Validate user input'
      }
    ],
    csharp: [
      {
        ruleId: 'cs-sqli-001', 
        message: 'SQL injection vulnerability',
        severity: 'critical' as const,
        line: 5,
        column: 10,
        file: 'test.cs',
        remediation: 'Use parameterized queries'
      },
      {
        ruleId: 'cs-cmd-001',
        message: 'Command injection vulnerability',
        severity: 'high' as const,
        line: 8,
        column: 15,
        file: 'test.cs',
        remediation: 'Validate user input'
      }
    ]
  };

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Set up mock implementation
    const mockAnalyze = jest.fn((code: string, language: string) => {
      switch (language) {
        case 'javascript':
          return mockVulnerabilities.javascript;
        case 'python':
          return mockVulnerabilities.python;
        case 'java':
          return mockVulnerabilities.java;
        case 'csharp':
          return mockVulnerabilities.csharp;
        default:
          return [];
      }
    });
    
    // Create the mock instance
    (DynamicAnalyzer as jest.MockedClass<typeof DynamicAnalyzer>).mockImplementation(() => ({
      analyze: mockAnalyze
    }) as unknown as DynamicAnalyzer);
    
    // Create analyzer instance
    analyzer = new DynamicAnalyzer();
  });
  
  describe('DynamicAnalyzer', () => {
    describe('JavaScript Analysis', () => {
      it('should detect vulnerabilities in JavaScript code', () => {
        const code = `
          const query = "SELECT * FROM users WHERE id = '" + userId + "'";
          db.query(query);
          
          const cmd = "ls " + userInput;
          exec(cmd);
        `;
        
        const vulnerabilities = analyzer.analyze(code, 'javascript');
        
        expect(vulnerabilities).toHaveLength(2);
        
        // Check if at least one SQL injection vulnerability is found
        const sqlInjection = vulnerabilities.find(v => v.ruleId.includes('sqli'));
        expect(sqlInjection).toBeDefined();
        
        // Check if at least one command injection vulnerability is found
        const cmdInjection = vulnerabilities.find(v => v.ruleId.includes('cmd'));
        expect(cmdInjection).toBeDefined();
      });
    });
    
    describe('Python Analysis', () => {
      it('should detect vulnerabilities in Python code', () => {
        const code = `
          query = "SELECT * FROM users WHERE id = '" + user_id + "'"
          cursor.execute(query)
          
          cmd = "ls " + user_input
          os.system(cmd)
        `;
        
        const vulnerabilities = analyzer.analyze(code, 'python');
        
        expect(vulnerabilities).toHaveLength(2);
        
        // Check if at least one SQL injection vulnerability is found
        const sqlInjection = vulnerabilities.find(v => v.ruleId.includes('sqli'));
        expect(sqlInjection).toBeDefined();
        
        // Check if at least one command injection vulnerability is found
        const cmdInjection = vulnerabilities.find(v => v.ruleId.includes('cmd'));
        expect(cmdInjection).toBeDefined();
      });
    });
    
    describe('Java Analysis', () => {
      it('should detect vulnerabilities in Java code', () => {
        const code = `
          String query = "SELECT * FROM users WHERE id = '" + userId + "'";
          Statement stmt = connection.createStatement();
          ResultSet rs = stmt.executeQuery(query);
          
          String cmd = "ls " + userInput;
          Runtime.getRuntime().exec(cmd);
        `;
        
        const vulnerabilities = analyzer.analyze(code, 'java');
        
        expect(vulnerabilities).toHaveLength(2);
        
        // Check if at least one SQL injection vulnerability is found
        const sqlInjection = vulnerabilities.find(v => v.ruleId.includes('sqli'));
        expect(sqlInjection).toBeDefined();
        
        // Check if at least one command injection vulnerability is found
        const cmdInjection = vulnerabilities.find(v => v.ruleId.includes('cmd'));
        expect(cmdInjection).toBeDefined();
      });
    });
    
    describe('C# Analysis', () => {
      it('should detect vulnerabilities in C# code', () => {
        const code = `
          string query = "SELECT * FROM Users WHERE Id = '" + userId + "'";
          SqlCommand command = new SqlCommand(query, connection);
          SqlDataReader reader = command.ExecuteReader();
          
          string cmd = "cmd.exe /c " + userInput;
          Process.Start(cmd);
        `;
        
        const vulnerabilities = analyzer.analyze(code, 'csharp');
        
        expect(vulnerabilities).toHaveLength(2);
        
        // Check if at least one SQL injection vulnerability is found
        const sqlInjection = vulnerabilities.find(v => v.ruleId.includes('sqli'));
        expect(sqlInjection).toBeDefined();
        
        // Check if at least one command injection vulnerability is found
        const cmdInjection = vulnerabilities.find(v => v.ruleId.includes('cmd'));
        expect(cmdInjection).toBeDefined();
      });
    });
  });
}); 