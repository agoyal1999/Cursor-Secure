import { Rule, Vulnerability } from '../interfaces';

export const csharpRules: Rule[] = [
  // SQL Injection
  {
    id: 'cs-sqli-001',
    name: 'SQL Injection',
    description: 'Potential SQL injection vulnerability detected in C# code.',
    severity: 'critical',
    category: 'Injection',
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Simple regex patterns to detect SQL injection vulnerabilities in C#
      const patterns = [
        // String concatenation in SQL queries
        /SqlCommand\s*\(\s*.*?\s*\+\s*.*?\)/g,
        // String formatting in queries
        /SqlCommand\s*\(\s*string\.Format\s*\(\s*.*?,\s*.*?\)\)/g,
        // String interpolation
        /SqlCommand\s*\(\s*\$".*?\{.*?\}.*?"\)/g
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          // Calculate line numbers for the match
          const lines = code.slice(0, match.index).split('\n');
          const line = lines.length;
          const column = lines[lines.length - 1].length + 1;
          
          vulnerabilities.push({
            ruleId: 'cs-sqli-001',
            message: 'Potential SQL injection vulnerability. Use parameterized queries with SqlParameter instead of string concatenation.',
            severity: 'critical',
            line,
            column
          });
        }
      });
      
      return vulnerabilities;
    }
  }
  // Additional C# rules would be added here
]; 