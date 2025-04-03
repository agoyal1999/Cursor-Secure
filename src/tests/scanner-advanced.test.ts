import { Scanner } from '../scanner';
import { ScanOptions, SupportedLanguage, Severity } from '../interfaces';

describe('Advanced Scanner Tests', () => {
  // Test custom rules
  describe('Custom Rules', () => {
    test('should load and apply custom rules', () => {
      const customRules = [
        {
          id: 'custom-js-eval-001',
          language: 'javascript',
          pattern: /eval\(/,
          message: 'Use of eval is discouraged',
          severity: 'high' as Severity,
          remediation: 'Avoid using eval',
          fix: {
            description: 'Consider alternatives to eval',
            replacement: 'JSON.parse() or Function constructor'
          }
        }
      ];
      
      const scanOptions: ScanOptions = {
        customRules,
        ignorePatterns: []
      };
      
      const scanner = new Scanner(scanOptions);
      
      const code = `
        function parseData(data) {
          return eval('(' + data + ')');
        }
      `;
      
      const result = scanner.scan(code, 'javascript', 'test.js');
      
      // Should find our custom rule vulnerability
      const customVulns = result.vulnerabilities.filter(v => v.ruleId === 'custom-js-eval-001');
      expect(customVulns.length).toBeGreaterThan(0);
      expect(customVulns[0].message).toBe('Use of eval is discouraged');
      expect(customVulns[0].severity).toBe('high');
    });
    
    test('should load custom rules for different languages', () => {
      const customRules = [
        {
          id: 'custom-py-eval-001',
          language: 'python',
          pattern: /eval\(/,
          message: 'Use of eval is discouraged in Python',
          severity: 'high' as Severity,
          remediation: 'Avoid using eval in Python',
          fix: {
            description: 'Consider safer alternatives',
            replacement: 'ast.literal_eval()'
          }
        }
      ];
      
      const scanOptions: ScanOptions = {
        customRules,
        ignorePatterns: []
      };
      
      const scanner = new Scanner(scanOptions);
      
      const code = `
        def parse_data(data):
            return eval(data)
      `;
      
      const result = scanner.scan(code, 'python', 'test.py');
      
      // Should find our custom rule vulnerability
      const customVulns = result.vulnerabilities.filter(v => v.ruleId === 'custom-py-eval-001');
      expect(customVulns.length).toBeGreaterThan(0);
      expect(customVulns[0].message).toBe('Use of eval is discouraged in Python');
    });
  });
  
  // Test edge cases
  describe('Edge Cases', () => {
    test('should handle empty code input', () => {
      const scanner = new Scanner();
      const result = scanner.scan('', 'javascript', 'empty.js');
      
      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.summary).toBeDefined();
      expect(result.summary!.total).toBe(0);
    });
    
    test('should handle code with only comments', () => {
      const scanner = new Scanner();
      const code = `
        // This is a comment
        /* 
         * Multi-line comment
         */
        // No actual code here
      `;
      
      const result = scanner.scan(code, 'javascript', 'comments.js');
      
      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.summary!.total).toBe(0);
    });
    
    test('should handle code with syntax errors', () => {
      const scanner = new Scanner();
      const code = `
        function brokenFunction() {
          const query = "SELECT * FROM users WHERE id = '" + userId + "'  // Missing closing quote
          return db.query(query);
        }
      `;
      
      // Should not throw an exception
      expect(() => {
        scanner.scan(code, 'javascript', 'broken.js');
      }).not.toThrow();
    });
    
    test('should handle unsupported language gracefully', () => {
      const scanner = new Scanner();
      const code = `
        fn main() {
            println!("Hello, world!");
        }
      `;
      
      // Rust is not supported, but shouldn't throw
      const result = scanner.scan(code, 'javascript', 'rust_code.rs');
      
      // Shouldn't find any js vulnerabilities in Rust code
      expect(result.vulnerabilities).toHaveLength(0);
    });
    
    test('should handle extremely long lines', () => {
      const scanner = new Scanner();
      // Create a very long line with a vulnerability in the middle
      let longLine = "const x = '";
      for (let i = 0; i < 1000; i++) {
        longLine += "a";
      }
      longLine += "' + userInput + '";
      for (let i = 0; i < 1000; i++) {
        longLine += "b";
      }
      longLine += "';";
      
      const result = scanner.scan(longLine, 'javascript', 'long.js');
      
      // Should still find the SQL injection vulnerability
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
    });
  });
  
  // Test all supported languages
  describe('Multi-Language Support', () => {
    test('should detect XSS vulnerabilities in Python', () => {
      const scanner = new Scanner();
      const code = `
        @app.route('/comment')
        def display_comment():
            comment = request.args.get('comment')
            response.write('<p>' + comment + '</p>')
            return response
      `;
      
      const result = scanner.scan(code, 'python', 'app.py');
      
      const xssVulns = result.vulnerabilities.filter(v => v.ruleId === 'py-xss-001');
      expect(xssVulns.length).toBeGreaterThan(0);
    });
    
    test('should detect XSS vulnerabilities in Java', () => {
      const scanner = new Scanner();
      const code = `
        @RequestMapping("/comment")
        public void displayComment(HttpServletResponse response) throws IOException {
            String comment = request.getParameter("comment");
            PrintWriter out = response.getWriter();
            out.println("<p>" + comment + "</p>");
        }
      `;
      
      const result = scanner.scan(code, 'java', 'CommentController.java');
      
      const xssVulns = result.vulnerabilities.filter(v => v.ruleId === 'java-xss-001');
      expect(xssVulns.length).toBeGreaterThan(0);
    });
    
    test('should detect XSS vulnerabilities in C#', () => {
      const scanner = new Scanner();
      const code = `
        [HttpGet]
        public ActionResult DisplayComment(string comment)
        {
            Response.Write("<p>" + comment + "</p>");
            return View();
        }
      `;
      
      const result = scanner.scan(code, 'csharp', 'CommentController.cs');
      
      const xssVulns = result.vulnerabilities.filter(v => v.ruleId === 'cs-xss-001');
      expect(xssVulns.length).toBeGreaterThan(0);
    });
  });
  
  // Test special options
  describe('ScanOptions', () => {
    test('should apply custom ignorePatterns', () => {
      const scanOptions: ScanOptions = {
        ignorePatterns: ['// SECURITY: ignore next line']
      };
      
      const scanner = new Scanner(scanOptions);
      
      const code = `
        function getUserData(userId) {
          // scan-ignore-file
          const query = "SELECT * FROM users WHERE id = '" + userId + "'";
          return db.query(query);
        }
      `;
      
      const result = scanner.scan(code, 'javascript', 'ignored.js');
      
      // Should not detect any vulnerabilities due to the ignore pattern
      expect(result.vulnerabilities).toHaveLength(0);
    });
    
    test('should handle multiple rules and excludeRules', () => {
      const scanOptions: ScanOptions = {
        rules: ['js-sqli-001'],  // Only include SQL injection rule, remove js-cmd-001
        ignorePatterns: []
      };
      
      const scanner = new Scanner(scanOptions);
      
      const code = `
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = '" + userId + "'";
          return db.query(query);
        }
        
        function executeCommand(cmd) {
          const { exec } = require('child_process');
          exec('ls ' + cmd);
        }
      `;
      
      const result = scanner.scan(code, 'javascript', 'test.js');
      
      // Should only find SQL injection, not command injection
      const sqlVulns = result.vulnerabilities.filter(v => v.ruleId === 'js-sqli-001');
      expect(sqlVulns.length).toBeGreaterThan(0);
      
      const cmdVulns = result.vulnerabilities.filter(v => v.ruleId === 'js-cmd-001');
      expect(cmdVulns).toHaveLength(0);
    });
  });
}); 