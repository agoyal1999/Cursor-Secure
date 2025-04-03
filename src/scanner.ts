import { Vulnerability, ScanResult, SupportedLanguage, ScanOptions, Severity } from './interfaces';

export class Scanner {
  private rules: Record<string, Record<string, any>> = {
    javascript: {
      'js-sqli-001': {
        pattern: /['"].*?\+\s*\w+/,
        message: 'Possible SQL injection vulnerability',
        severity: 'critical' as Severity,
        fix: {
          description: 'Use parameterized queries instead of string concatenation',
          replacement: 'Use db.query("SELECT * FROM users WHERE id = ?", [userId])'
        }
      },
      'js-xss-001': {
        pattern: /\.innerHTML\s*=\s*\w+/,
        message: 'Possible XSS vulnerability',
        severity: 'critical' as Severity,
        fix: {
          description: 'Use textContent instead of innerHTML or sanitize input',
          replacement: 'element.textContent = sanitizedContent'
        }
      },
      'js-cmd-001': {
        pattern: /exec\(\s*(['"].*?\+|.*?\+\s*['"])/,
        message: 'Command injection vulnerability',
        severity: 'critical' as Severity,
        fix: {
          description: 'Avoid using user input in shell commands',
          replacement: 'Use a safer alternative or validate user input extensively'
        }
      },
      'js-jwt-001': {
        pattern: /jwt\.verify\(\s*\w+\s*,\s*\w+\s*\)/,
        message: 'JWT verification without algorithm specification',
        severity: 'high' as Severity,
        fix: {
          description: 'Specify algorithm in JWT verification',
          replacement: 'jwt.verify(token, secretKey, { algorithms: ["HS256"] })'
        }
      },
      'js-path-001': {
        pattern: /\.readFileSync\(\s*(['"]\.\/|['"].*?\+)/,
        message: 'Possible path traversal vulnerability',
        severity: 'critical' as Severity,
        fix: {
          description: 'Validate and sanitize file paths',
          replacement: 'Use path.normalize() and validate paths are within allowed directory'
        }
      },
      'js-crypto-001': {
        pattern: /\.createHash\(\s*['"]md5['"]/,
        message: 'Weak cryptographic hash function (MD5)',
        severity: 'high' as Severity,
        fix: {
          description: 'Use stronger hash algorithm',
          replacement: 'crypto.createHash("sha256").update(password).digest("hex")'
        }
      }
    },
    python: {
      'py-sqli-001': {
        pattern: /(query|sql)\s*=.*?%\s*\w+/,
        message: 'Possible SQL injection vulnerability in Python',
        severity: 'critical' as Severity,
        fix: {
          description: 'Use parameterized queries instead of string formatting',
          replacement: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        }
      },
      'py-xss-001': {
        pattern: /\.write\(\s*.*\+/,
        message: 'Possible XSS vulnerability in Python',
        severity: 'critical' as Severity,
        fix: {
          description: 'Escape user input before writing to HTML',
          replacement: 'response.write(html.escape(user_input))'
        }
      },
      'py-cmd-001': {
        pattern: /(os\.system|os\.popen|subprocess\.Popen|subprocess\.call|subprocess\.run|exec|eval)\(/,
        message: 'Command injection vulnerability in Python',
        severity: 'critical' as Severity,
        fix: {
          description: 'Avoid using user input in shell commands',
          replacement: 'Use a safer alternative or validate user input extensively'
        }
      }
    },
    java: {
      'java-sqli-001': {
        pattern: /String\s+query\s*=\s*["'].*?['"]\s*\+/i,
        message: 'Possible SQL injection vulnerability in Java',
        severity: 'critical' as Severity,
        fix: {
          description: 'Use PreparedStatement instead of concatenation',
          replacement: 'PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?")'
        }
      },
      'java-xss-001': {
        pattern: /(println|print)\(\s*.*?\+/,
        message: 'Possible XSS vulnerability in Java',
        severity: 'critical' as Severity,
        fix: {
          description: 'Escape user input before printing to HTML',
          replacement: 'out.println(StringEscapeUtils.escapeHtml4(userInput))'
        }
      }
    },
    csharp: {
      'cs-sqli-001': {
        pattern: /string\s+query\s*=\s*["'].*?['"]\s*\+/i,
        message: 'Possible SQL injection vulnerability in C#',
        severity: 'critical' as Severity,
        fix: {
          description: 'Use parameterized queries instead of string concatenation',
          replacement: 'cmd.CommandText = "SELECT * FROM users WHERE id = @userId";\ncmd.Parameters.AddWithValue("@userId", userId);'
        }
      },
      'cs-xss-001': {
        pattern: /Response\.Write\(\s*.*?\+/i,
        message: 'Possible XSS vulnerability in C#',
        severity: 'critical' as Severity,
        fix: {
          description: 'Encode user input before writing to HTML',
          replacement: 'Response.Write(HttpUtility.HtmlEncode(userInput))'
        }
      }
    }
  };

  private options: ScanOptions;

  constructor(options?: ScanOptions) {
    this.options = options || { ignorePatterns: [] };
    // Initialize scanner with default rules or load custom rules if provided
    if (this.options.customRules) {
      this.loadCustomRules(this.options.customRules);
    }
  }

  private loadCustomRules(customRules: any[]): void {
    // Load custom rules into the rules object
    customRules.forEach(rule => {
      const language = rule.language || 'javascript';
      if (!this.rules[language]) {
        this.rules[language] = {};
      }
      this.rules[language][rule.id] = rule;
    });
  }

  public scan(code: string, language: SupportedLanguage, filename: string = 'unknown.js'): ScanResult {
    const vulnerabilities: Vulnerability[] = [];
    const languageRules = this.rules[language] || {};

    // Check if this file should be ignored
    if (this.shouldIgnoreFile(code)) {
      return { vulnerabilities: [], summary: this.createEmptySummary() };
    }

    // Filter rules if specific rules are requested
    const activeRules = this.filterRules(languageRules);

    // Apply each rule to the code
    for (const ruleId in activeRules) {
      const rule = activeRules[ruleId];
      const pattern = rule.pattern;
      const lines = code.split('\n');

      // Search for vulnerabilities in each line
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (pattern.test(line)) {
          const match = line.match(pattern);
          if (match) {
            const lineNumber = i + 1;
            const column = match.index || 0;
            vulnerabilities.push({
              ruleId,
              message: rule.message,
              severity: rule.severity,
              line: lineNumber,
              column,
              file: filename,
              remediation: rule.remediation,
              fix: rule.fix ? {
                description: rule.fix.description,
                replacement: rule.fix.replacement,
                range: {
                  start: { line: lineNumber, column },
                  end: { line: lineNumber, column: column + match[0].length }
                }
              } : undefined
            });
          }
        }
      }
    }

    // Generate summary
    const summary = {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length,
      error: vulnerabilities.filter(v => v.severity === 'error').length,
      warning: vulnerabilities.filter(v => v.severity === 'warning').length,
      info: vulnerabilities.filter(v => v.severity === 'info').length
    };

    return {
      vulnerabilities,
      summary
    };
  }

  private shouldIgnoreFile(code: string): boolean {
    // Check for directives in the code to ignore scanning
    return code.includes('// scan-ignore-file') || code.includes('/* scan-ignore-file */');
  }

  private filterRules(languageRules: Record<string, any>): Record<string, any> {
    // If specific rules are requested, filter them
    if (this.options.rules && this.options.rules.length > 0) {
      const filteredRules: Record<string, any> = {};
      Object.keys(languageRules).forEach(ruleId => {
        if (this.options.rules!.includes(ruleId)) {
          filteredRules[ruleId] = languageRules[ruleId];
        }
      });
      return filteredRules;
    }

    // If rules to exclude are specified, filter them out
    if (this.options.excludeRules && this.options.excludeRules.length > 0) {
      const filteredRules: Record<string, any> = { ...languageRules };
      this.options.excludeRules.forEach(ruleId => {
        delete filteredRules[ruleId];
      });
      return filteredRules;
    }

    return languageRules;
  }

  private createEmptySummary() {
    return {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      error: 0,
      warning: 0,
      info: 0
    };
  }
} 