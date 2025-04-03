// Auto-generated security tests
const { securityCheck } = require('../src/security');

describe('Security vulnerability tests', () => {

  test('Test js-sqli-001 with payload: \' OR 1=1 --', () => {
    // Validate vulnerability: SQL Injection vulnerability
    const input = `' OR 1=1 --`;
    
    // Assert that security check rejects the malicious input
    expect(() => securityCheck(input)).toThrow();
  });

  test('Test js-sqli-001 with payload: \'; DROP TABLE users;', () => {
    // Validate vulnerability: SQL Injection vulnerability
    const input = `'; DROP TABLE users; --`;
    
    // Assert that security check rejects the malicious input
    expect(() => securityCheck(input)).toThrow();
  });

  test('Test js-sqli-001 with payload: \' UNION SELECT usern', () => {
    // Validate vulnerability: SQL Injection vulnerability
    const input = `' UNION SELECT username, password FROM users --`;
    
    // Assert that security check rejects the malicious input
    expect(() => securityCheck(input)).toThrow();
  });
});
