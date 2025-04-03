# Testing the Security Vulnerability Scanner

This directory contains tests and test fixtures for the security vulnerability scanner.

## Test Structure

- `scanner.test.ts`: Tests for the core scanner functionality
- `samples/`: Contains sample code with known vulnerabilities
  - `vulnerable.js`: JavaScript code with common security vulnerabilities

## Running Tests

To run the tests:

```bash
npm test
```

To run tests with coverage:

```bash
npm run test:coverage
```

To run tests in watch mode during development:

```bash
npm run test:watch
```

## Test Coverage Goals

We aim for high test coverage of the scanner functionality:

- 80% line coverage
- 80% function coverage
- 70% branch coverage
- 80% statement coverage

## Adding New Tests

When adding new tests:

1. Add a test case in the appropriate test file or create a new one
2. If testing a new vulnerability type, add a sample to the `samples/` directory
3. Use descriptive test names that explain what's being tested
4. Test both positive cases (detecting vulnerabilities) and negative cases (no false positives)

## Testing Approach

Our testing strategy involves:

1. **Unit Testing**: Testing individual components like rules, parsers, etc.
2. **Integration Testing**: Testing the scanner as a whole
3. **Sample-based Testing**: Using real-world vulnerable code samples
4. **Edge Case Testing**: Testing boundary conditions and unusual inputs

## Sample Vulnerabilities

The `vulnerable.js` file contains examples of:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Insecure JWT Usage
- Path Traversal
- Weak Cryptography
- Prototype Pollution
- Insecure Random Values
- NoSQL Injection
- Insecure Deserialization
- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF) 