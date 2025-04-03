import { Scanner } from '../scanner';
import { ScanOptions, Vulnerability, ScanResult } from '../interfaces';

describe('Scanner Basic Tests', () => {
  describe('Constructor', () => {
    test('should initialize with default options', () => {
      const scanner = new Scanner();
      expect(scanner).toBeInstanceOf(Scanner);
    });

    test('should initialize with custom options', () => {
      const options: ScanOptions = {
        ignorePatterns: ['// ignore'],
        rules: ['js-sqli-001']
      };
      const scanner = new Scanner(options);
      expect(scanner).toBeInstanceOf(Scanner);
    });
  });

  describe('Scan Method', () => {
    test('should scan JavaScript code and detect SQL injection', () => {
      const scanner = new Scanner();
      const code = `
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = '" + userId + "'";
          return db.query(query);
        }
      `;
      
      const result = scanner.scan(code, 'javascript', 'test.js');
      
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.vulnerabilities[0].ruleId).toBe('js-sqli-001');
      expect(result.vulnerabilities[0].severity).toBe('critical');
    });

    test('should scan Python code and detect SQL injection', () => {
      const scanner = new Scanner();
      const code = `
        def get_user_data(user_id):
            query = "SELECT * FROM users WHERE id = '%s'" % user_id
            return db.execute(query)
      `;
      
      const result = scanner.scan(code, 'python', 'test.py');
      
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.vulnerabilities[0].ruleId).toBe('py-sqli-001');
      expect(result.vulnerabilities[0].severity).toBe('critical');
    });

    test('should scan Java code and detect SQL injection', () => {
      const scanner = new Scanner();
      const code = `
        public User getUserData(String userId) {
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            return db.executeQuery(query);
        }
      `;
      
      const result = scanner.scan(code, 'java', 'Test.java');
      
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.vulnerabilities[0].ruleId).toBe('java-sqli-001');
      expect(result.vulnerabilities[0].severity).toBe('critical');
    });

    test('should scan C# code and detect SQL injection', () => {
      const scanner = new Scanner();
      const code = `
        public User GetUserData(string userId)
        {
            string query = "SELECT * FROM users WHERE id = '" + userId + "'";
            return db.ExecuteQuery(query);
        }
      `;
      
      const result = scanner.scan(code, 'csharp', 'Test.cs');
      
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.vulnerabilities[0].ruleId).toBe('cs-sqli-001');
      expect(result.vulnerabilities[0].severity).toBe('critical');
    });
  });

  describe('File Ignoring', () => {
    test('should ignore file with scan-ignore-file directive', () => {
      const scanner = new Scanner();
      const code = `
        // scan-ignore-file
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = '" + userId + "'";
          return db.query(query);
        }
      `;
      
      const result = scanner.scan(code, 'javascript', 'ignored.js');
      
      expect(result.vulnerabilities.length).toBe(0);
      expect(result.summary!.total).toBe(0);
    });

    test('should ignore file with /* scan-ignore-file */ directive', () => {
      const scanner = new Scanner();
      const code = `
        /* scan-ignore-file */
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = '" + userId + "'";
          return db.query(query);
        }
      `;
      
      const result = scanner.scan(code, 'javascript', 'ignored.js');
      
      expect(result.vulnerabilities.length).toBe(0);
      expect(result.summary!.total).toBe(0);
    });
  });

  describe('Rule Filtering', () => {
    test('should only apply specified rules', () => {
      const options: ScanOptions = {
        rules: ['js-sqli-001'], // Only check for SQL injection
        ignorePatterns: []
      };
      
      const scanner = new Scanner(options);
      
      const code = `
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = '" + userId + "'";
          return db.query(query);
        }
        
        function renderContent(content) {
          element.innerHTML = content; // XSS vulnerability, but should be ignored
        }
      `;
      
      const result = scanner.scan(code, 'javascript', 'filtered.js');
      
      expect(result.vulnerabilities.length).toBe(1);
      expect(result.vulnerabilities[0].ruleId).toBe('js-sqli-001');
    });

    test('should exclude specified rules', () => {
      const options: ScanOptions = {
        excludeRules: ['js-sqli-001'], // Exclude SQL injection checks
        ignorePatterns: []
      };
      
      const scanner = new Scanner(options);
      
      const code = `
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = '" + userId + "'";
          return db.query(query);
        }
        
        function renderContent(content) {
          element.innerHTML = content; // XSS vulnerability, should be detected
        }
      `;
      
      const result = scanner.scan(code, 'javascript', 'excluded.js');
      
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.vulnerabilities[0].ruleId).not.toBe('js-sqli-001');
    });
  });

  describe('Summary Generation', () => {
    test('should generate correct summary of vulnerabilities', () => {
      const scanner = new Scanner();
      const code = `
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = '" + userId + "'";
          return db.query(query);
        }
        
        function renderContent(content) {
          element.innerHTML = content;
        }
        
        function getHash(password) {
          return crypto.createHash('md5').update(password).digest('hex');
        }
      `;
      
      const result = scanner.scan(code, 'javascript', 'summary.js');
      
      expect(result.summary!).toBeDefined();
      expect(result.summary!.total).toBe(result.vulnerabilities.length);
      expect(result.summary!.critical).toBe(result.vulnerabilities.filter(v => v.severity === 'critical').length);
      expect(result.summary!.high).toBe(result.vulnerabilities.filter(v => v.severity === 'high').length);
    });
  });
}); 