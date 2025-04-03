import { Rule, Vulnerability } from '../interfaces';

export const javascriptRules: Rule[] = [
  // SQL Injection
  {
    id: 'js-sqli-001',
    name: 'SQL Injection',
    description: 'Potential SQL injection vulnerability detected. User input should be parameterized or properly escaped.',
    severity: 'critical',
    category: 'Injection',
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Simple regex patterns to detect SQL injection vulnerabilities
      const patterns = [
        // SQL concatenation patterns
        /('|"|`)\s*\+\s*\w+\s*\+\s*('|"|`)/g,
        // Common database query methods with concatenated variables
        /\.(query|execute|executeQuery)\s*\(\s*('|"|`).*?\$\{.*?\}/g,
        // Template literals in database queries
        /\.(query|execute|executeQuery)\s*\(\s*`.*?\$\{.*?\}/g
      ];
      
      // Check each pattern
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          // Calculate line and column using the match index
          const lineInfo = getLineAndColumn(code, match.index);
          
          vulnerabilities.push({
            ruleId: 'js-sqli-001',
            message: 'Potential SQL injection vulnerability. Use parameterized queries or ORM instead of concatenating user input.',
            severity: 'critical',
            line: lineInfo.line,
            column: lineInfo.column,
            fix: {
              description: 'Use parameterized queries instead of string concatenation',
              replacement: '/* Use parameterized queries, e.g., db.query("SELECT * FROM users WHERE id = ?", [userId]) */',
              range: {
                start: { line: lineInfo.line, column: lineInfo.column },
                end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
              }
            }
          });
        }
      });
      
      return vulnerabilities;
    }
  },
  
  // Cross-Site Scripting (XSS)
  {
    id: 'js-xss-001',
    name: 'Cross-Site Scripting (XSS)',
    description: 'Potential XSS vulnerability detected. User input should be properly escaped before being rendered to HTML.',
    severity: 'critical',
    category: 'Injection',
    references: [
      'https://owasp.org/www-community/attacks/xss/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Patterns to detect potential XSS vulnerabilities
      const patterns = [
        // DOM manipulation with user input
        /document\.write\s*\(\s*.*?\)/g,
        /\.innerHTML\s*=\s*.*?(?:params|query|input|value|data)/gi,
        /\$\s*\(\s*('|"|`)[^)]+\1\s*\)\.html\s*\(\s*.*?(?:params|query|input|value|data)/gi,
        // React dangerouslySetInnerHTML
        /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*.*?\}\s*\}/g
      ];
      
      // Check each pattern
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          const lineInfo = getLineAndColumn(code, match.index);
          
          vulnerabilities.push({
            ruleId: 'js-xss-001',
            message: 'Potential XSS vulnerability. User input should be properly sanitized before being inserted into HTML.',
            severity: 'critical',
            line: lineInfo.line,
            column: lineInfo.column,
            fix: {
              description: 'Use a sanitization library or built-in sanitization methods',
              replacement: '/* Use a sanitization library like DOMPurify: DOMPurify.sanitize(userInput) */',
              range: {
                start: { line: lineInfo.line, column: lineInfo.column },
                end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
              }
            }
          });
        }
      });
      
      return vulnerabilities;
    }
  },
  
  // Insecure JWT Validation
  {
    id: 'js-jwt-001',
    name: 'Insecure JWT Validation',
    description: 'Potential insecure JWT validation. The "none" algorithm should be explicitly disallowed.',
    severity: 'critical',
    category: 'Authentication',
    references: [
      'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
      'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for JWT verify calls without algorithm specification
      const patterns = [
        /jwt\.verify\s*\(\s*.*?\s*,\s*.*?\s*\)/g,
        /jsonwebtoken.*?\.verify\s*\(\s*.*?\s*,\s*.*?\s*\)/g
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          // Check if there's no algorithm specified
          if (!code.slice(match.index, match.index + match[0].length).includes('algorithms')) {
            const lineInfo = getLineAndColumn(code, match.index);
            
            vulnerabilities.push({
              ruleId: 'js-jwt-001',
              message: 'Potential insecure JWT validation. Always specify algorithms to prevent "none" algorithm attacks.',
              severity: 'critical',
              line: lineInfo.line,
              column: lineInfo.column,
              fix: {
                description: 'Explicitly specify allowed algorithms',
                replacement: 'jwt.verify(token, secret, { algorithms: ["HS256", "RS256"] })',
                range: {
                  start: { line: lineInfo.line, column: lineInfo.column },
                  end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
                }
              }
            });
          }
        }
      });
      
      return vulnerabilities;
    }
  },

  // Command Injection
  {
    id: 'js-cmd-001',
    name: 'Command Injection',
    description: 'Potential command injection vulnerability detected. User input should not be used in shell commands.',
    severity: 'critical',
    category: 'Injection',
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for command execution with user input
      const patterns = [
        /child_process\.exec\s*\(\s*.*?\+.*?\)/g,
        /child_process\.execSync\s*\(\s*.*?\+.*?\)/g,
        /child_process\.spawn\s*\(\s*.*?\+.*?\)/g,
        /child_process\.spawnSync\s*\(\s*.*?\+.*?\)/g,
        /child_process\.execFile\s*\(\s*.*?\+.*?\)/g,
        /child_process\.execFileSync\s*\(\s*.*?\+.*?\)/g,
        /exec\s*\(\s*.*?\+.*?\)/g,
        /execSync\s*\(\s*.*?\+.*?\)/g,
        /spawn\s*\(\s*.*?\+.*?\)/g,
        /spawnSync\s*\(\s*.*?\+.*?\)/g,
        // Template literal usage in commands
        /child_process\.exec\s*\(\s*`.*?\$\{.*?\}.*?`.*?\)/g,
        /child_process\.execSync\s*\(\s*`.*?\$\{.*?\}.*?`.*?\)/g
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          const lineInfo = getLineAndColumn(code, match.index);
          
          vulnerabilities.push({
            ruleId: 'js-cmd-001',
            message: 'Potential command injection vulnerability. Do not use user input directly in shell commands.',
            severity: 'critical',
            line: lineInfo.line,
            column: lineInfo.column,
            fix: {
              description: 'Use child_process.execFile or .spawn with arguments as an array instead of string concatenation',
              replacement: '/* Use child_process.execFile to safely pass arguments: execFile("ls", ["-la", directory]) */',
              range: {
                start: { line: lineInfo.line, column: lineInfo.column },
                end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
              }
            }
          });
        }
      });
      
      return vulnerabilities;
    }
  },

  // Path Traversal
  {
    id: 'js-path-001',
    name: 'Path Traversal',
    description: 'Potential path traversal vulnerability detected. User input should be properly validated before being used in file operations.',
    severity: 'critical',
    category: 'Broken Access Control',
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
      'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for file operations with user input
      const patterns = [
        /fs\.readFile\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi,
        /fs\.readFileSync\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi,
        /fs\.writeFile\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi,
        /fs\.writeFileSync\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi,
        /path\.join\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi,
        /path\.resolve\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          const lineInfo = getLineAndColumn(code, match.index);
          
          vulnerabilities.push({
            ruleId: 'js-path-001',
            message: 'Potential path traversal vulnerability. Validate and sanitize user input before using it in file operations.',
            severity: 'critical',
            line: lineInfo.line,
            column: lineInfo.column,
            fix: {
              description: 'Validate file paths, use path.normalize, and restrict to intended directories',
              replacement: '/* Sanitize path: path.normalize(filePath).replace(/^(\\.\\.[\/\\\\])+/, "") and use path.join with a base directory */',
              range: {
                start: { line: lineInfo.line, column: lineInfo.column },
                end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
              }
            }
          });
        }
      });
      
      return vulnerabilities;
    }
  },

  // Insecure Randomness
  {
    id: 'js-random-001',
    name: 'Insecure Randomness',
    description: 'Use of cryptographically weak random number generator detected. Use crypto.randomBytes or crypto.getRandomValues instead.',
    severity: 'high',
    category: 'Cryptographic Failures',
    references: [
      'https://owasp.org/www-community/vulnerabilities/Insecure_Randomness',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for insecure random number generation
      const patterns = [
        /Math\.random\s*\(\)/g,
        /\*\s*Math\.random\s*\(\)/g,
        /Math\.random\s*\(\)\s*\*/g,
        /parseInt\s*\(\s*Math\.random\s*\(\)/g
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          // Ignore Math.random when not used for security purposes
          // This is a simplified check and might have false positives
          const surroundingCode = code.substring(Math.max(0, match.index - 100), Math.min(code.length, match.index + match[0].length + 100));
          const securityContexts = [
            'token', 'password', 'secret', 'key', 'auth', 'secure', 'crypt', 'random', 'salt', 'nonce', 'iv'
          ];
          
          // Only flag if it seems to be used in a security context
          if (securityContexts.some(context => surroundingCode.includes(context))) {
            const lineInfo = getLineAndColumn(code, match.index);
            
            vulnerabilities.push({
              ruleId: 'js-random-001',
              message: 'Use of insecure Math.random() for security-sensitive operation. Use crypto.randomBytes() instead.',
              severity: 'high',
              line: lineInfo.line,
              column: lineInfo.column,
              fix: {
                description: 'Use cryptographically secure random number generation',
                replacement: 'crypto.randomBytes(size)',
                range: {
                  start: { line: lineInfo.line, column: lineInfo.column },
                  end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
                }
              }
            });
          }
        }
      });
      
      return vulnerabilities;
    }
  },

  // Weak Cryptography
  {
    id: 'js-crypto-001',
    name: 'Weak Cryptography',
    description: 'Use of weak cryptographic algorithms or insufficient key lengths detected.',
    severity: 'high',
    category: 'Cryptographic Failures',
    references: [
      'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for weak cryptographic algorithms
      const patterns = [
        // MD5
        /crypto\.createHash\s*\(\s*['"`]md5['"`]/g,
        // SHA1
        /crypto\.createHash\s*\(\s*['"`]sha1['"`]/g,
        // DES
        /crypto\.createCipheriv\s*\(\s*['"`]des['"`]/g,
        // RC4
        /crypto\.createCipheriv\s*\(\s*['"`]rc4['"`]/g,
        // 3DES
        /crypto\.createCipheriv\s*\(\s*['"`]des3['"`]/g,
        /crypto\.createCipheriv\s*\(\s*['"`]des-ede3['"`]/g
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          const lineInfo = getLineAndColumn(code, match.index);
          
          let algorithm = 'weak algorithm';
          if (match[0].includes('md5')) algorithm = 'MD5';
          else if (match[0].includes('sha1')) algorithm = 'SHA1';
          else if (match[0].includes('des3') || match[0].includes('des-ede3')) algorithm = '3DES';
          else if (match[0].includes('des')) algorithm = 'DES';
          else if (match[0].includes('rc4')) algorithm = 'RC4';
          
          vulnerabilities.push({
            ruleId: 'js-crypto-001',
            message: `Use of weak cryptographic algorithm: ${algorithm}. Use modern algorithms like AES-256-GCM or SHA-256/SHA-3.`,
            severity: 'high',
            line: lineInfo.line,
            column: lineInfo.column,
            fix: {
              description: 'Use modern cryptographic algorithms',
              replacement: algorithm.includes('Hash') ? 
                'crypto.createHash("sha256")' : 
                'crypto.createCipheriv("aes-256-gcm", key, iv)',
              range: {
                start: { line: lineInfo.line, column: lineInfo.column },
                end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
              }
            }
          });
        }
      });
      
      return vulnerabilities;
    }
  },

  // NoSQL Injection
  {
    id: 'js-nosqli-001',
    name: 'NoSQL Injection',
    description: 'Potential NoSQL injection vulnerability detected. User input should be properly validated before being used in database queries.',
    severity: 'critical',
    category: 'Injection',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/MongoDB_Security_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for NoSQL injection patterns
      const patterns = [
        // MongoDB operator in user-supplied object
        /\.\s*(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany|replaceOne)\s*\(\s*\{\s*.*?(?:req|request|params|query|body|input|data)/gi,
        // MongoDB with string concatenation
        /\.\s*(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany|replaceOne)\s*\(\s*['"`].*?['"`]\s*\+\s*.*?\)/gi,
        // MongoDB with string template
        /\.\s*(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany|replaceOne)\s*\(\s*`.*?\$\{.*?\}.*?`\s*\)/gi,
        // Direct use of $where or $expr operators with user input
        /\$where\s*:\s*(?:['"`].*?['"`]\s*\+|`.*?\$\{)/g,
        /\$expr\s*:\s*(?:['"`].*?['"`]\s*\+|`.*?\$\{)/g
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          const lineInfo = getLineAndColumn(code, match.index);
          
          vulnerabilities.push({
            ruleId: 'js-nosqli-001',
            message: 'Potential NoSQL injection vulnerability. Validate and sanitize user inputs before using in MongoDB queries.',
            severity: 'critical',
            line: lineInfo.line,
            column: lineInfo.column,
            fix: {
              description: 'Use input validation and parameterized queries',
              replacement: '/* Use validated parameters: db.collection.find({ field: sanitizedValue }) */',
              range: {
                start: { line: lineInfo.line, column: lineInfo.column },
                end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
              }
            }
          });
        }
      });
      
      return vulnerabilities;
    }
  },

  // Prototype Pollution
  {
    id: 'js-proto-001',
    name: 'Prototype Pollution',
    description: 'Potential prototype pollution vulnerability detected. Validate object keys and use safe alternatives to Object.assign/merge.',
    severity: 'high',
    category: 'Broken Access Control',
    references: [
      'https://owasp.org/www-community/vulnerabilities/Prototype_pollution',
      'https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for patterns that could lead to prototype pollution
      const patterns = [
        // Recursive object merging without key validation
        /(?:merge|extend|cloneDeep|defaultsDeep)\s*\(\s*.*?(?:req|request|params|query|body|input|data)/gi,
        // Object property assignment using bracket notation with variable
        /\[\s*.*?(?:req|request|params|query|body|input|data).*?\]\s*=/gi,
        // Object.assign with target being populated from user input
        /Object\.assign\s*\(\s*.*?(?:req|request|params|query|body|input|data)/gi,
        // Setting constructor or prototype properties
        /\.__proto__\s*=/g,
        /\.constructor\s*=/g,
        /\.prototype\s*=/g
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          const lineInfo = getLineAndColumn(code, match.index);
          
          vulnerabilities.push({
            ruleId: 'js-proto-001',
            message: 'Potential prototype pollution vulnerability. Validate object keys and avoid assigning to special properties.',
            severity: 'high',
            line: lineInfo.line,
            column: lineInfo.column,
            fix: {
              description: 'Use safe object operations and validate keys',
              replacement: match[0].includes('__proto__') || match[0].includes('constructor') || match[0].includes('prototype') ?
                '/* Do not modify built-in objects or their prototypes */' :
                '/* Use Object.create(null) or validate keys before merging/assigning: Object.keys(obj).forEach(k => { if(!k.startsWith("__") && !["constructor", "prototype"].includes(k)) target[k] = obj[k]; }) */',
              range: {
                start: { line: lineInfo.line, column: lineInfo.column },
                end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
              }
            }
          });
        }
      });
      
      return vulnerabilities;
    }
  },

  // Insecure Deserialization
  {
    id: 'js-deserial-001',
    name: 'Insecure Deserialization',
    description: 'Potential insecure deserialization vulnerability detected. Avoid deserializing untrusted data.',
    severity: 'critical',
    category: 'Insecure Deserialization',
    references: [
      'https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization',
      'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for dangerous deserialization patterns
      const patterns = [
        // Node.js serialize/unserialize
        /(?:unserialize|deserialize)\s*\(\s*.*?(?:req|request|params|query|body|input|data)/gi,
        // eval with JSON
        /eval\s*\(\s*.*?(?:req|request|params|query|body|input|data)/gi,
        // JSON.parse with user input
        /JSON\.parse\s*\(\s*.*?(?:req|request|params|query|body|input|data)/gi,
        // YAML.parse with user input
        /(?:yaml|yml)\.(?:parse|load|safeLoad)\s*\(\s*.*?(?:req|request|params|query|body|input|data)/gi
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          const lineInfo = getLineAndColumn(code, match.index);
          
          let severity = 'high';
          let message = 'Potential insecure deserialization vulnerability.';
          
          // Eval is particularly dangerous
          if (match[0].includes('eval')) {
            severity = 'critical';
            message = 'Extremely dangerous eval() with user input. Never use eval with untrusted data.';
          }
          
          vulnerabilities.push({
            ruleId: 'js-deserial-001',
            message,
            severity: severity as any,
            line: lineInfo.line,
            column: lineInfo.column,
            fix: {
              description: 'Avoid deserializing untrusted data or use safe alternatives',
              replacement: match[0].includes('JSON.parse') ? 
                '/* Use JSON schema validation before parsing: validator.validate(schema, JSON.parse(data)) */' :
                '/* Do not deserialize untrusted data. If necessary, use safe deserializers with schema validation */',
              range: {
                start: { line: lineInfo.line, column: lineInfo.column },
                end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
              }
            }
          });
        }
      });
      
      return vulnerabilities;
    }
  },
  
  // Broken Access Control
  {
    id: 'js-access-001',
    name: 'Broken Access Control',
    description: 'Potential access control vulnerability detected. Implement proper authorization checks.',
    severity: 'high',
    category: 'Broken Access Control',
    references: [
      'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control',
      'https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for routes without authorization checks
      const patterns = [
        // Express routes definitions
        /(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`]\/admin.*?['"`]/gi,
        /(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`].*?\/(?:users?|accounts?)\/.*?['"`]/gi,
        // API endpoint definitions
        /\@(?:Get|Post|Put|Delete|Patch)\s*\(\s*['"`]\/admin.*?['"`]/gi,
        /\@(?:Get|Post|Put|Delete|Patch)\s*\(\s*['"`].*?\/(?:users?|accounts?)\/.*?['"`]/gi
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          // Check for middleware that might handle authorization
          const surroundingCode = code.slice(Math.max(0, match.index - 200), match.index + match[0].length + 200);
          const hasAuthCheck = surroundingCode.match(/auth|isAuthenticated|requiresAuth|checkPermission|isAdmin|verifyToken|checkAuth|ensureAuth|canAccess|authorize|authGuard/i);
          
          if (!hasAuthCheck) {
            const lineInfo = getLineAndColumn(code, match.index);
            
            vulnerabilities.push({
              ruleId: 'js-access-001',
              message: 'Potential broken access control. Implement proper authorization checks for sensitive routes.',
              severity: 'high',
              line: lineInfo.line,
              column: lineInfo.column,
              fix: {
                description: 'Add middleware for authorization check',
                replacement: '/* Add authorization middleware: app.get("/admin/route", authMiddleware, (req, res) => {...}) */',
                range: {
                  start: { line: lineInfo.line, column: lineInfo.column },
                  end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
                }
              }
            });
          }
        }
      });
      
      return vulnerabilities;
    }
  },

  // Cross-Site Request Forgery (CSRF)
  {
    id: 'js-csrf-001',
    name: 'Cross-Site Request Forgery (CSRF)',
    description: 'Potential CSRF vulnerability detected. Implement CSRF tokens and SameSite cookies.',
    severity: 'high',
    category: 'Broken Access Control',
    references: [
      'https://owasp.org/www-community/attacks/csrf',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for potential CSRF vulnerabilities
      const patterns = [
        // Express post/put/delete routes without CSRF protection
        /(?:app|router)\.(?:post|put|delete|patch)\s*\(\s*.*?\)/g,
        // Cookie setting without proper attributes
        /(?:res|response)\.cookie\s*\(\s*.*?\)/g,
        // Sessions without CSRF protection
        /session\s*\(\s*\{.*?\}\s*\)/g
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          // Check if there's CSRF protection in place
          const surroundingCode = code.slice(Math.max(0, match.index - 200), match.index + match[0].length + 200);
          const hasCSRFProtection = surroundingCode.match(/csrf|csurf|xsrf|antiforgery|csrfToken|csrfProtection/i);
          
          if (!hasCSRFProtection) {
            const lineInfo = getLineAndColumn(code, match.index);
            
            vulnerabilities.push({
              ruleId: 'js-csrf-001',
              message: 'Potential CSRF vulnerability. Implement CSRF tokens or use SameSite cookies.',
              severity: 'high',
              line: lineInfo.line,
              column: lineInfo.column,
              fix: {
                description: 'Add CSRF protection',
                replacement: '/* Add CSRF protection: app.use(csrf()); and verify csrfToken in forms */',
                range: {
                  start: { line: lineInfo.line, column: lineInfo.column },
                  end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
                }
              }
            });
          }
        }
      });
      
      return vulnerabilities;
    }
  },

  // Server-Side Request Forgery (SSRF)
  {
    id: 'js-ssrf-001',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Potential SSRF vulnerability detected. Validate and sanitize URLs before making requests.',
    severity: 'high',
    category: 'Injection',
    references: [
      'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
      'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
    ],
    check: (code: string, language) => {
      const vulnerabilities: Vulnerability[] = [];
      
      // Check for HTTP requests with user-controlled URLs
      const patterns = [
        // HTTP requests with user input in URL
        /https?\.(?:get|request)\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi,
        /(?:axios|fetch|got|request|superagent)\.(?:get|post|put|delete|patch)\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi,
        /(?:axios|fetch|got|request|superagent)\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi,
        // URL parsing with user input
        /new URL\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi,
        /url\.parse\s*\(\s*.*?(?:req|request|params|query|body|input|data).*?\)/gi
      ];
      
      patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          const lineInfo = getLineAndColumn(code, match.index);
          
          vulnerabilities.push({
            ruleId: 'js-ssrf-001',
            message: 'Potential SSRF vulnerability. Validate and filter URLs before making requests to prevent server-side request forgery.',
            severity: 'high',
            line: lineInfo.line,
            column: lineInfo.column,
            fix: {
              description: 'Implement URL validation and allowlist approach',
              replacement: '/* Validate URL: const parsedUrl = new URL(url); if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) throw new Error("Domain not allowed"); */',
              range: {
                start: { line: lineInfo.line, column: lineInfo.column },
                end: { line: lineInfo.line, column: lineInfo.column + match[0].length }
              }
            }
          });
        }
      });
      
      return vulnerabilities;
    }
  }
];

/**
 * Helper function to calculate line and column numbers from character index
 */
function getLineAndColumn(code: string, index: number): { line: number; column: number } {
  const lines = code.slice(0, index).split('\n');
  const line = lines.length;
  const column = lines[lines.length - 1].length + 1;
  return { line, column };
} 