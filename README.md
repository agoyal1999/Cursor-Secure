# Cursor Secure Scanner

A comprehensive security vulnerability scanner for code that integrates with popular IDEs and development workflows to identify, explain, and remediate security issues in real-time.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Test Coverage](https://img.shields.io/badge/coverage-27%25-red.svg)]()

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Supported Languages](#supported-languages)
- [Installation](#installation)
  - [VSCode Extension](#vscode-extension)
  - [IntelliJ Plugin](#intellij-plugin)
  - [Eclipse Plugin](#eclipse-plugin)
  - [CLI Tool](#cli-tool)
- [Usage](#usage)
  - [IDE Integration](#ide-integration)
  - [Command Line](#command-line)
  - [Git Hooks](#git-hooks)
- [Configuration](#configuration)
- [Vulnerability Rules](#vulnerability-rules)
- [Dynamic Analysis](#dynamic-analysis)
- [Security Audit Overview](#security-audit-overview)
- [Contributing](#contributing)
- [License](#license)
- [Limitations and Disclaimers](#limitations-and-disclaimers)

## Overview

Cursor Secure Scanner is designed to help developers identify and fix security vulnerabilities during the development process, rather than discovering them later in security audits. By integrating directly into IDEs and development workflows, it provides real-time feedback on potential security issues along with actionable recommendations for fixing them.

## Features

- **Real-time Vulnerability Detection**: Detects security issues as you code
- **Multi-language Support**: Analyzes JavaScript, Python, Java, and C#
- **IDE Integration**: Works with VSCode, IntelliJ, and Eclipse
- **Command Line Interface**: Scan files or projects from the terminal
- **Git Hooks Integration**: Prevents vulnerable code from being committed or pushed
- **Detailed Explanations**: Provides descriptions and context for each vulnerability
- **Fix Suggestions**: Offers actionable remediation advice
- **Customizable Rules**: Configure severity levels and enable/disable specific rules
- **Extensive Rule Set**: Covers OWASP Top 10 and other security standards
- **Dynamic Analysis**: Runtime behavior analysis for deeper vulnerability detection
- **Taint Tracking**: Follows untrusted data through application execution paths
- **Dependency Scanning**: Identifies known vulnerabilities in third-party dependencies
- **Comprehensive Security Audit**: Generates detailed security reports with recommendations

## Supported Languages

| Language   | Static Analysis | Dynamic Analysis | Coverage Level |
|------------|----------------|------------------|-----------------|
| JavaScript | ✅             | ✅               | Comprehensive  |
| Python     | ✅             | ⚠️ Partial       | Basic          |
| Java       | ✅             | ⚠️ Limited       | Basic          |
| C#         | ✅             | ⚠️ Experimental  | Limited        |

## Installation

### Prerequisites

- Node.js 14.x or higher
- npm 6.x or higher

### VSCode Extension

```bash
# Install from VS Code Marketplace
code --install-extension cursor-secure-scanner

# Or manually install
cd extensions/vscode
npm install
npm run vscode:package
code --install-extension cursor-secure-scanner-*.vsix
```

### IntelliJ Plugin

```bash
# Install from IntelliJ Marketplace
# Or manually install
cd extensions/intellij
./gradlew buildPlugin
# Install from disk in IntelliJ: Preferences > Plugins > ⚙️ > Install Plugin from Disk...
```

### Eclipse Plugin

```bash
# Install from Eclipse Marketplace
# Or manually install
cd extensions/eclipse
mvn package
# Install from disk in Eclipse: Help > Install New Software > Add > Archive...
```

### CLI Tool

```bash
# Install globally
npm install -g cursor-secure

# Or install locally
npm install --save-dev cursor-secure
```

## Usage

### IDE Integration

After installing the extension/plugin for your IDE, the scanner automatically begins analyzing your code in real-time.

#### VSCode

- Enable/disable scanning: `Ctrl+Shift+P` > `Secure Scanner: Enable/Disable`
- Manually scan file: `Ctrl+Shift+P` > `Secure Scanner: Scan Current File`
- Scan workspace: `Ctrl+Shift+P` > `Secure Scanner: Scan Workspace`
- View security panel: Click the shield icon in the sidebar

#### IntelliJ IDEA

- Enable/disable scanning: `Tools > Cursor Secure Scanner > Enable/Disable`
- Manually scan file: `Tools > Cursor Secure Scanner > Scan Current File`
- Scan project: `Tools > Cursor Secure Scanner > Scan Project`
- View security panel: `View > Tool Windows > Cursor Secure Scanner`

#### Eclipse

- Enable/disable scanning: `Cursor Secure > Enable/Disable Scanner`
- Manually scan file: `Cursor Secure > Scan Current File`
- Scan project: `Cursor Secure > Scan Project`
- View security panel: `Window > Show View > Cursor Secure Scanner`

### Command Line

```bash
# Scan a single file
cursor-secure scan file.js

# Scan a directory
cursor-secure scan ./src

# Scan with specific configuration
cursor-secure scan --config ./.securerc.json ./src

# Generate a JSON report
cursor-secure scan --output report.json --format json ./src

# Scan only staged git files
cursor-secure scan --staged-only

# Scan and fail if critical vulnerabilities are found (for CI/CD)
cursor-secure scan --fail-on critical ./src

# Run with dynamic analysis
cursor-secure scan --dynamic ./src
```

### Git Hooks

```bash
# Install git hooks
cursor-secure install-hooks

# This will add:
# - pre-commit hook: Scans staged files before committing
# - pre-push hook: Performs a more thorough scan before pushing
```

## Configuration

Create a `.securerc.json` file in your project root to customize the scanner:

```json
{
  "scannerConfig": {
    "blockOnCritical": true,
    "blockOnError": false,
    "scanOnSave": true,
    "scanOnType": true,
    "enablePreCommitHook": true,
    "enablePrePushHook": true,
    "enableDynamicAnalysis": true,
    "ignorePatterns": [
      "**/node_modules/**",
      "**/dist/**",
      "**/build/**",
      "**/vendor/**"
    ]
  },
  "rules": {
    "js-sqli-001": "critical",
    "js-xss-001": "critical",
    "py-cmd-001": "error",
    "java-sqli-001": "critical",
    "cs-xss-001": "critical",
    "dynamic-cmd-001": "critical",
    "taint-sql-001": "critical",
    "dep-js-lodash": "high"
  },
  "customRulesPath": "./custom-rules.js"
}
```

## Vulnerability Rules

Cursor Secure Scanner detects a wide range of security vulnerabilities:

### Injection Vulnerabilities
- SQL Injection
- NoSQL Injection
- OS Command Injection
- Code Injection
- LDAP Injection
- XPath Injection

### Cross-Site Vulnerabilities
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Cross-Origin Resource Sharing Misconfigurations

### Authentication & Authorization
- Hardcoded Credentials
- Insecure Authentication
- Improper Access Control
- JWT Misconfigurations

### Data Protection
- Insecure Cryptography
- Weak Hashing Algorithms
- Insufficient TLS Configuration
- Unvalidated Data Serialization/Deserialization

### Server-Side Vulnerabilities
- Server-Side Request Forgery (SSRF)
- Path Traversal
- File Inclusion
- XML External Entity (XXE)

### Client-Side Vulnerabilities
- Insecure Direct Object References
- DOM-based Vulnerabilities
- Client-Side Storage Issues

### API Security
- GraphQL Vulnerabilities
- REST API Security Issues
- Improper API Key Handling

### Other Security Issues
- Prototype Pollution
- Race Conditions
- Insecure Random Values
- Open Redirect

## Dynamic Analysis

The scanner now includes comprehensive dynamic analysis capabilities:

### Taint Tracking
Follows the flow of untrusted data through the application to detect how user inputs can lead to security vulnerabilities:
- Identifies all sources of untrusted input (HTTP requests, user inputs, etc.)
- Tracks data flow through variables and function calls
- Alerts when tainted data reaches sensitive sinks (database queries, command execution, etc.)
- Supports JavaScript, with limited support for Python, Java, and C#

### Runtime Behavior Analysis
Executes code in a sandboxed environment to detect issues that only manifest during runtime:
- Monitors file system operations for path traversal attempts
- Tracks network requests to identify SSRF vulnerabilities
- Logs command executions to detect injection attempts
- Observes cryptographic operations for weak algorithm usage
- Provides detailed execution context to understand vulnerability patterns

### Dependency Analysis
Scans project dependencies against a database of known vulnerable packages:
- Detects outdated packages with security issues
- Provides specific vulnerability information and remediation advice
- Supports multiple dependency formats (package.json, requirements.txt, pom.xml, .csproj)
- Checks against a regularly updated database of CVEs

### Test Generation
Automatically creates security test cases to validate vulnerability findings:
- Generates language-appropriate test files (Jest, unittest, JUnit, NUnit)
- Creates tests with payloads targeting each detected vulnerability
- Helps validate security fixes by providing regression tests
- Supports custom payload generation for specific vulnerability types

### How Dynamic Analysis Works

1. **Code Instrumentation**: The scanner first instruments the code by adding tracking mechanisms that monitor runtime behavior without changing functionality.

2. **Sandbox Execution**: Instrumented code runs in a secure sandbox to prevent any actual damage while capturing behavior.

3. **Source and Sink Identification**: The system identifies sources of untrusted data (like user inputs) and dangerous sinks (like database queries).

4. **Execution Tracing**: As code executes, the scanner traces data flow, recording all operations and tracking tainted values.

5. **Vulnerability Detection**: When tainted data reaches a sensitive sink without proper sanitization, the scanner flags it as a vulnerability.

6. **Audit Report Generation**: Results are combined with static analysis findings to provide a comprehensive security assessment.

To enable dynamic analysis:

```bash
# In CLI
cursor-secure scan --dynamic ./src

# In configuration file
{
  "scannerConfig": {
    "enableDynamicAnalysis": true,
    "dynamicAnalysisTimeout": 30,
    "trackTaint": true,
    "checkDependencies": true,
    "generateTests": true
  }
}
```

## Troubleshooting

### Common Issues

#### Installation Problems

- **Dependency Errors**: If you encounter dependency errors during installation, try clearing your npm cache with `npm cache clean --force` and reinstalling.
- **Permission Issues**: If you have permission errors, try running the installation with admin privileges or use `sudo` on Unix systems.

#### Scanner Not Working

- **Path Issues**: Ensure the scanner is correctly added to your PATH environment variable.
- **Configuration Problems**: Verify your `.securerc.json` file has valid JSON syntax and appropriate settings.
- **IDE Integration**: For IDE extensions, make sure you have the correct version that matches your IDE version.

#### False Positives/Negatives

- **Rule Tuning**: Adjust rule sensitivity in your configuration file to reduce false positives.
- **Excluded Paths**: Check that your critical code isn't in an excluded path.
- **Custom Rules**: Consider writing custom rules for your specific codebase patterns.

### Error Messages

#### "Cannot find rules for language X"
- Make sure the language is supported and properly configured in your settings.

#### "Error during dynamic analysis"
- Check that your code doesn't contain syntax errors that prevent execution.
- Ensure your code doesn't require external resources that aren't available during analysis.

#### "Dependency check failed"
- Verify you have internet access for checking vulnerability databases.
- Check that your dependency files are correctly formatted.

### Getting Help

- **GitHub Issues**: Submit issues on our GitHub repository for bugs or feature requests.
- **Documentation**: Refer to the full documentation at [cursor-secure.docs](https://cursor-secure.docs).
- **Community Forums**: Join our community forums to get help from other users.

## Security Audit Overview

The scanner now provides comprehensive security audit reports to minimize manual review effort:

### Audit Features
- **Complete Vulnerability Assessment**: Combines static, dynamic, and dependency analysis
- **Severity Classification**: Categorizes issues by impact and exploitability
- **Risk Prioritization**: Highlights critical issues requiring immediate attention
- **File-level Risk Analysis**: Identifies your most vulnerable files
- **Vulnerability Categorization**: Groups issues by type for easier remediation planning
- **Actionable Recommendations**: Provides specific guidance for addressing vulnerabilities
- **Multiple Report Formats**: Outputs in HTML, JSON, Markdown, or plain text

### Generating Reports

```bash
# Generate a security audit report
cursor-secure audit --output security-report.html --format html ./src

# Include dynamic analysis in the audit
cursor-secure audit --dynamic --output security-report.html ./src

# Specify severity threshold
cursor-secure audit --severity-threshold medium --output security-report.md --format md ./src
```

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Add your changes
4. Run tests: `npm test`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Limitations and Disclaimers

### Important Disclaimers

- **No 100% Guarantee**: While Cursor Secure Scanner is designed to detect a wide range of security vulnerabilities, no security tool can guarantee the complete absence of security issues. It should be used as part of a comprehensive security strategy, not as the only line of defense.

- **False Positives and Negatives**: Like all security analysis tools, the scanner may report false positives (flagging code that isn't actually vulnerable) or miss some vulnerabilities (false negatives). Always use professional judgment when evaluating results.

- **Evolving Threats**: Security vulnerabilities and attack techniques evolve constantly. Regular updates to the scanner are necessary to maintain effectiveness against emerging threats.

### Current Limitations

- **Non-JavaScript Language Support**: While the scanner supports multiple languages, the level of analysis is most comprehensive for JavaScript. Python, Java, and C# support is being actively improved.
  - **Python**: Dynamic analysis covers basic patterns but may miss framework-specific vulnerabilities
  - **Java**: Taint tracking is limited to common patterns; full JVM integration is in development
  - **C#**: Dynamic analysis is experimental and may not detect all vulnerabilities

- **Dynamic Analysis Constraints**:
  - Requires appropriate execution environment
  - May not detect vulnerabilities that only appear in specific runtime conditions
  - Complex applications with many external dependencies may not be fully analyzable

- **Runtime Performance**: Enabling dynamic analysis will increase scan time significantly, especially for large codebases. Consider using it selectively on security-critical components.

- **Development Status**: This tool is under active development. Some features may be experimental or incomplete. Check the documentation or release notes for the latest status.

### Best Practices

For the most effective security posture:

1. **Multiple Tools**: Use Cursor Secure Scanner alongside other security analysis tools
2. **Regular Manual Reviews**: Conduct periodic manual code reviews focusing on security
3. **Security Training**: Ensure developers understand security principles and common vulnerabilities
4. **Penetration Testing**: Regularly test applications with professional penetration testing
5. **Stay Updated**: Keep the scanner and its rule database up-to-date

The Cursor Secure Scanner is most effective when used as one component of a defense-in-depth security strategy.

## Multi-Language Support

The Cursor Security Scanner provides robust security analysis across multiple programming languages:

### JavaScript/TypeScript
- Detection of XSS, CSRF, SQL injection, command injection, and path traversal vulnerabilities
- Analysis of unsafe code patterns (eval, document.write, innerHTML)
- NodeJS-specific vulnerability detection (directory traversal, unsafe redirects)

### Python
- Detection of SQL injection vulnerabilities (sqlite3, psycopg2, mysql)
- Command injection checks (os.system, subprocess.call)
- Path traversal detection in file operations
- Framework-specific checks for Flask and Django applications
- Template injection vulnerability detection

### Java
- SQL injection detection (JDBC, executeQuery, prepareStatement)
- Command execution vulnerabilities (Runtime.exec, ProcessBuilder)
- Path traversal in file operations (java.io.File)
- XML External Entity (XXE) vulnerability detection
- Unsafe deserialization checks (ObjectInputStream)
- Spring and Jakarta EE security checks

### C#
- SQL injection in ADO.NET (SqlCommand, OleDbCommand)
- Command injection detection (Process.Start, ProcessStartInfo)
- Path traversal vulnerabilities (File, Directory operations)
- XXE vulnerabilities in XML processing
- Unsafe deserialization (BinaryFormatter)
- ASP.NET MVC CSRF protection checks
- Open redirect vulnerability detection

## Configuration

You can configure the scanner with various options:

```javascript
const options = {
  severityThreshold: 'medium', // 'info', 'warning', 'medium', 'high', 'critical'
  includePatterns: ['**/*.js', '**/*.py', '**/*.java', '**/*.cs'],
  excludePatterns: ['**/node_modules/**', '**/test/**'],
  dynamicAnalysis: true,
  reportFormat: 'json' // 'json', 'html', 'markdown', 'text'
};

const result = await scanner.scanDirectory('./my-project', options);
``` 