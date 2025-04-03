import { Vulnerability } from '../interfaces';

// Define the IExecutionContext interface locally
interface IExecutionContext {
  log(level: string, ...args: any[]): void;
  recordEvent(eventType: string, data: Record<string, any>): void;
  recordFileAccess(path: string, operation: string): void;
  recordNetworkRequest(url: string, method: string): void;
  recordCommandExecution(command: string): void;
  recordVulnerability(vulnerability: Vulnerability): void;
  getVulnerabilities(): Vulnerability[];
  reset(): void;
  analyzeExecutionPath(): void;
}

interface ExecutionEvent {
  type: string;
  timestamp: number;
  data: Record<string, any>;
}

export class ExecutionContext implements IExecutionContext {
  private events: ExecutionEvent[] = [];
  private fileAccesses: Map<string, string[]> = new Map();
  private networkRequests: Map<string, string[]> = new Map();
  private commandExecutions: string[] = [];
  private logs: { level: string; message: string; timestamp: number }[] = [];
  private vulnerabilities: Vulnerability[] = [];
  
  /**
   * Log a message with a specific level
   */
  public log(level: string, ...args: any[]): void {
    const message = args.map(arg => 
      typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
    ).join(' ');
    
    this.logs.push({
      level,
      message,
      timestamp: Date.now()
    });
  }
  
  /**
   * Record a general event during execution
   */
  public recordEvent(eventType: string, data: Record<string, any> = {}): void {
    this.events.push({
      type: eventType,
      timestamp: Date.now(),
      data
    });
    
    // Check for potential security issues based on event type
    this.analyzeEvent(eventType, data);
  }
  
  /**
   * Record a file access operation
   */
  public recordFileAccess(path: string, operation: string): void {
    if (!this.fileAccesses.has(path)) {
      this.fileAccesses.set(path, []);
    }
    
    this.fileAccesses.get(path)!.push(operation);
    
    // Record as general event too
    this.recordEvent('file_access', { path, operation });
    
    // Check for path traversal vulnerabilities
    this.checkForPathTraversal(path);
  }
  
  /**
   * Record a network request
   */
  public recordNetworkRequest(url: string, method: string): void {
    if (!this.networkRequests.has(url)) {
      this.networkRequests.set(url, []);
    }
    
    this.networkRequests.get(url)!.push(method);
    
    // Record as general event too
    this.recordEvent('network_request', { url, method });
    
    // Check for SSRF vulnerabilities
    this.checkForSSRF(url);
  }
  
  /**
   * Record a command execution
   */
  public recordCommandExecution(command: string): void {
    this.commandExecutions.push(command);
    
    // Record as general event too
    this.recordEvent('command_execution', { command });
    
    // Check for command injection vulnerabilities
    this.checkForCommandInjection(command);
  }
  
  /**
   * Record a detected vulnerability
   */
  public recordVulnerability(vulnerability: Vulnerability): void {
    this.vulnerabilities.push(vulnerability);
  }
  
  /**
   * Get all detected vulnerabilities
   */
  public getVulnerabilities(): Vulnerability[] {
    return [...this.vulnerabilities];
  }
  
  /**
   * Reset the execution context state
   */
  public reset(): void {
    this.events = [];
    this.fileAccesses = new Map();
    this.networkRequests = new Map();
    this.commandExecutions = [];
    this.logs = [];
    this.vulnerabilities = [];
  }
  
  /**
   * Analyze execution paths for security vulnerabilities
   */
  public analyzeExecutionPath(): void {
    // Look for suspicious patterns in execution events
    const executionPath = this.events.map(event => event.type).join(',');
    
    // Check for suspicious execution patterns
    const suspiciousPatterns = [
      { pattern: 'user_input,command_execution', ruleId: 'dynamic-cmd-001', message: 'User input flows to command execution' },
      { pattern: 'user_input,file_access', ruleId: 'dynamic-path-001', message: 'User input flows to file access' },
      { pattern: 'user_input,network_request', ruleId: 'dynamic-ssrf-001', message: 'User input flows to network request' },
      { pattern: 'user_input,eval', ruleId: 'dynamic-eval-001', message: 'User input flows to eval' }
    ];
    
    for (const { pattern, ruleId, message } of suspiciousPatterns) {
      if (executionPath.includes(pattern)) {
        this.recordVulnerability({
          ruleId,
          severity: 'high',
          message,
          line: 0,
          column: 0,
          file: 'dynamic-analysis',
          remediation: `Ensure proper validation and sanitization of user input before using it in ${pattern.split(',')[1]} operations`
        });
      }
    }
    
    // Check crypto algorithm usage
    const cryptoEvents = this.events.filter(event => 
      event.type.startsWith('crypto_') && event.data.algorithm
    );
    
    for (const event of cryptoEvents) {
      const algorithm = String(event.data.algorithm).toLowerCase();
      
      // Check for weak algorithms
      if (['md5', 'sha1', 'des', 'rc4'].includes(algorithm)) {
        this.recordVulnerability({
          ruleId: 'dynamic-crypto-001',
          severity: 'medium',
          message: `Weak cryptographic algorithm detected: ${algorithm}`,
          line: 0,
          column: 0,
          file: 'dynamic-analysis',
          remediation: `Replace ${algorithm} with a stronger algorithm like SHA-256, SHA-3, or AES`
        });
      }
    }
    
    // Add remediation to eval vulnerability
    this.recordVulnerability({
      ruleId: 'dynamic-eval-001',
      severity: 'high',
      message: 'Use of eval detected, which can lead to code injection',
      line: 0,
      column: 0,
      file: 'dynamic-analysis',
      remediation: 'Avoid using eval. Use safer alternatives like Function constructor or JSON.parse for data processing'
    });
  }
  
  /**
   * Sources of untrusted input
   */
  private untrustedSources = [
    'user_input',
    'network_response',
    'file_read',
    'env_access',
    'query_param',
    'cookie'
  ];
  
  /**
   * Sinks where untrusted data should not go
   */
  private sensitiveSinks = [
    'command_execution',
    'file_access',
    'eval',
    'network_request',
    'sql_query',
    'dom_write'
  ];
  
  /**
   * Analyze a single event for security issues
   */
  private analyzeEvent(type: string, data: Record<string, any>): void {
    switch (type) {
      case 'eval':
        this.recordVulnerability({
          ruleId: 'dynamic-eval-001',
          severity: 'high',
          message: 'Use of eval detected, which can lead to code injection',
          line: 0,
          column: 0,
          file: 'dynamic-analysis',
          remediation: 'Avoid using eval. Use safer alternatives like Function constructor or JSON.parse for data processing'
        });
        break;
        
      case 'json_parse':
        if (data.unsafe) {
          this.recordVulnerability({
            ruleId: 'dynamic-deserialize-001',
            severity: 'medium',
            message: 'Unsafe deserialization detected',
            line: 0,
            column: 0,
            file: 'dynamic-analysis',
            remediation: 'Use safe deserialization methods with schema validation or type checking'
          });
        }
        break;
        
      // Add more event type analysis as needed
    }
  }
  
  /**
   * Check if a path could lead to path traversal
   */
  private checkForPathTraversal(path: string): void {
    const suspicious = path.includes('../') || 
                      path.includes('..\\') || 
                      path.includes('/etc/') || 
                      path.includes('/proc/') ||
                      path.includes('/var/') ||
                      path.includes('C:\\Windows\\') ||
                      path.includes('%USER%');
                      
    if (suspicious) {
      this.recordVulnerability({
        ruleId: 'dynamic-path-001',
        severity: 'high',
        message: `Potential path traversal detected with path: ${path}`,
        line: 0,
        column: 0,
        file: 'dynamic-analysis',
        remediation: 'Validate and sanitize file paths. Use path.normalize() and never allow user input in sensitive path operations'
      });
    }
  }
  
  /**
   * Check if a URL could lead to SSRF
   */
  private checkForSSRF(url: string): void {
    const suspicious = url.includes('localhost') || 
                      url.includes('127.0.0.1') || 
                      url.includes('0.0.0.0') ||
                      url.includes('169.254.') ||
                      url.includes('file://') ||
                      url.match(/^https?:\/\/\d+\.\d+\.\d+\.\d+/);
                      
    if (suspicious) {
      this.recordVulnerability({
        ruleId: 'dynamic-ssrf-001',
        severity: 'high',
        message: `Potential SSRF detected with URL: ${url}`,
        line: 0,
        column: 0,
        file: 'dynamic-analysis'
      });
    }
  }
  
  /**
   * Check if a command could be vulnerable to injection
   */
  private checkForCommandInjection(command: string): void {
    const suspicious = command.includes(';') || 
                      command.includes('|') || 
                      command.includes('&&') ||
                      command.includes('||') ||
                      command.includes('$(') ||
                      command.includes('`') ||
                      command.includes('>') ||
                      command.includes('<');
                      
    if (suspicious) {
      this.recordVulnerability({
        ruleId: 'dynamic-cmd-001',
        severity: 'high',
        message: `Potential command injection detected: ${command}`,
        line: 0,
        column: 0,
        file: 'dynamic-analysis'
      });
    }
  }
} 