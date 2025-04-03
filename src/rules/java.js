"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.javaRules = void 0;
exports.javaRules = [
    // SQL Injection
    {
        id: 'java-sqli-001',
        name: 'SQL Injection',
        description: 'Potential SQL injection vulnerability detected in Java code.',
        severity: 'critical',
        category: 'Injection',
        references: [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        ],
        check: (code, language) => {
            const vulnerabilities = [];
            // Simple regex patterns to detect SQL injection vulnerabilities in Java
            const patterns = [
                // String concatenation in JDBC queries
                /executeQuery\s*\(\s*.*?\s*\+\s*.*?\)/g,
                /prepareStatement\s*\(\s*.*?\s*\+\s*.*?\)/g,
                // String formatting in queries
                /executeQuery\s*\(\s*String\.format\s*\(\s*.*?,\s*.*?\)\)/g
            ];
            patterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(code)) !== null) {
                    // Calculate line numbers for the match
                    const lines = code.slice(0, match.index).split('\n');
                    const line = lines.length;
                    const column = lines[lines.length - 1].length + 1;
                    vulnerabilities.push({
                        ruleId: 'java-sqli-001',
                        message: 'Potential SQL injection vulnerability. Use PreparedStatement with placeholders instead of string concatenation.',
                        severity: 'critical',
                        line,
                        column
                    });
                }
            });
            return vulnerabilities;
        }
    }
    // Additional Java rules would be added here
];
//# sourceMappingURL=java.js.map