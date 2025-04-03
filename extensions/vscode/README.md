# Secure Scanner for Visual Studio Code

A lightweight vulnerability scanner extension that provides real-time security feedback within Visual Studio Code.

## Features

- **Real-time vulnerability scanning** as you code
- **Pre-commit and pre-push hooks** to prevent insecure code from being committed or pushed
- **Inline annotations** showing detected vulnerabilities with suggested fixes
- **Support for multiple languages**: JavaScript, TypeScript, Python, Java, and C#
- **Customizable security rules** based on industry standards like the OWASP Top Ten

## Quick Demo

![Secure Scanner Demo](images/demo.gif)

## How It Works

Secure Scanner continuously analyzes your code as you write it, checking for common security vulnerabilities such as:

- SQL Injection
- Cross-Site Scripting (XSS)
- Insecure JWT Validation
- Command Injection
- Insecure Deserialization
- And many more...

When a potential vulnerability is detected, the extension highlights the issue directly in your code and provides a description of the problem along with suggested fixes.

## Extension Settings

This extension contributes the following settings:

* `secureScanner.enableRealTimeScanning`: Enable real-time scanning of code (default: true)
* `secureScanner.enablePreCommitHooks`: Enable pre-commit hooks to scan code before committing (default: true)
* `secureScanner.enablePrePushHooks`: Enable pre-push hooks to scan code before pushing (default: true)
* `secureScanner.blockOnCritical`: Block commits and pushes if critical vulnerabilities are found (default: true)
* `secureScanner.blockOnError`: Block commits and pushes if error-level vulnerabilities are found (default: false)
* `secureScanner.customRulesPath`: Path to custom security rules
* `secureScanner.ignorePatterns`: Patterns to ignore when scanning for vulnerabilities (default: ["**/node_modules/**", "**/dist/**", "**/build/**"])

## Commands

* `Secure Scanner: Scan for Security Vulnerabilities` - Scan the current file for security vulnerabilities
* `Secure Scanner: Scan Entire Project for Security Vulnerabilities` - Scan all files in the project for security vulnerabilities

## Usage Tips

1. **Real-Time Scanning**: By default, Secure Scanner analyzes your code as you type. You can disable this in the settings if you prefer manual scanning.

2. **Manual Scanning**: Use the command `Secure Scanner: Scan for Security Vulnerabilities` to manually scan the current file.

3. **Project-wide Scanning**: Use the command `Secure Scanner: Scan Entire Project for Security Vulnerabilities` to scan your entire project for security issues.

4. **Custom Rules**: Create your own security rules by specifying a path to a custom rules directory in the settings.

## Feedback and Contributions

This extension is open source! We welcome feedback and contributions to improve the extension and add new security rules.

## License

MIT 