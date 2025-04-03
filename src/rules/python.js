"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pythonRules = void 0;
exports.pythonRules = [
    // SQL Injection
    {
        id: 'py-sqli-001',
        name: 'SQL Injection',
        description: 'Potential SQL injection vulnerability detected in Python code.',
        severity: 'critical',
        category: 'Injection',
        references: [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        ],
        check: (code, language) => {
            const vulnerabilities = [];
            // Simple regex patterns to detect SQL injection vulnerabilities in Python
            const patterns = [
                // String concatenation with SQL
                /cursor\.execute\s*\(\s*(['"`]).*?\s*\+\s*.*?\1/g,
                // String formatting
                /cursor\.execute\s*\(\s*(['"`]).*?%.*?\1/g,
                // f-strings
                /cursor\.execute\s*\(\s*f(['"`]).*?\{.*?\}.*?\1/g
            ];
            patterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(code)) !== null) {
                    // Calculate line numbers for the match
                    const lines = code.slice(0, match.index).split('\n');
                    const line = lines.length;
                    const column = lines[lines.length - 1].length + 1;
                    vulnerabilities.push({
                        ruleId: 'py-sqli-001',
                        message: 'Potential SQL injection vulnerability. Use parameterized queries instead of string concatenation.',
                        severity: 'critical',
                        line,
                        column
                    });
                }
            });
            return vulnerabilities;
        }
    }
    // Additional Python rules would be added here
];
//# sourceMappingURL=python.js.map