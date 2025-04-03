import * as vm from 'vm';
import * as path from 'path';
import * as fs from 'fs';
import { ExecutionContext } from './context';
import { TaintTracker } from './taint-tracker';
import { TestGenerator, TestCase } from './test-generator';
import { SupportedLanguage, Vulnerability } from '../interfaces';

export class RuntimeAnalyzer {
  private executionContext: ExecutionContext;
  private taintTracker: TaintTracker;
  private testGenerator: TestGenerator;
  
  constructor() {
    this.executionContext = new ExecutionContext();
    this.taintTracker = new TaintTracker();
    this.testGenerator = new TestGenerator();
  }
  
  /**
   * Analyze JavaScript code in a sandboxed environment
   */
  public async analyzeJavaScript(code: string, staticVulnerabilities: Vulnerability[]): Promise<Vulnerability[]> {
    try {
      // Reset context and taint tracker
      this.executionContext.reset();
      this.taintTracker.reset();
      
      // Generate test cases for each static vulnerability
      const testCases = this.testGenerator.generateTests(code, 'javascript', staticVulnerabilities);
      
      // Instrument code with taint tracking
      let instrumentedCode;
      try {
        instrumentedCode = this.taintTracker.instrumentCode(code, 'javascript');
        
        // Fix common syntax issues in the instrumented code
        instrumentedCode = instrumentedCode
          .replace(/innerHTML\s*=\s*__checkSink\('dom',\s*(.*?)\);/g, "innerHTML = __checkSink('dom', $1);")
          .replace(/exec\s*\(\s*__checkSink\('command',\s*(.*?)\);/g, "exec(__checkSink('command', $1));")
          .replace(/query\s*\(\s*__checkSink\('sql',\s*(.*?)\);/g, "query(__checkSink('sql', $1));")
          .replace(/eval\s*\(\s*__checkSink\('eval',\s*(.*?)\);/g, "eval(__checkSink('eval', $1));")
          .replace(/readFile\s*\(\s*__checkSink\('file_path',\s*(.*?)\);/g, "readFile(__checkSink('file_path', $1));")
          .replace(/fetch\s*\(\s*__checkSink\('url',\s*(.*?)\);/g, "fetch(__checkSink('url', $1));");
      } catch (error) {
        console.error('Error instrumenting code:', error);
        instrumentedCode = code; // Use original code if instrumentation fails
      }
      
      // Setup sandbox context
      const sandbox = this.createSandbox();
      
      // Execute the instrumented code
      const script = new vm.Script(instrumentedCode);
      const context = vm.createContext(sandbox);
      script.runInContext(context);
      
      // Run each test case
      const dynamicVulnerabilities = await this.runTestCases(testCases, sandbox);
      
      // Get all detected vulnerabilities
      const taintVulnerabilities = this.taintTracker.getVulnerabilities();
      const contextVulnerabilities = this.executionContext.getVulnerabilities();
      
      // Return combined vulnerabilities (including static ones)
      return [
        ...staticVulnerabilities,
        ...taintVulnerabilities,
        ...contextVulnerabilities,
        ...dynamicVulnerabilities
      ];
    } catch (error) {
      console.error('Error executing JavaScript code:', error);
      // Even if execution fails, return at least the static vulnerabilities
      return [...staticVulnerabilities];
    }
  }
  
  /**
   * Create a sandboxed environment with monitoring hooks
   */
  private createSandbox(): Record<string, any> {
    // Setup monitored environment
    const sandbox: Record<string, any> = {
      console: {
        log: (...args: any[]) => this.executionContext.log('info', ...args),
        error: (...args: any[]) => this.executionContext.log('error', ...args),
        warn: (...args: any[]) => this.executionContext.log('warning', ...args),
        info: (...args: any[]) => this.executionContext.log('info', ...args),
      },
      setTimeout: (callback: Function, delay: number) => setTimeout(() => {
        this.executionContext.log('info', `Timeout executed after ${delay}ms`);
        callback();
      }, delay),
      __taintTracker: this.taintTracker,
      __executionContext: this.executionContext,
      
      // Mock browser APIs
      document: this.createMockDocument(),
      window: {},
      localStorage: this.createMockStorage(),
      sessionStorage: this.createMockStorage(),
      
      // Mock Node.js modules
      require: (module: string) => this.mockRequire(module),
      
      // Global objects
      Buffer: {
        from: (data: string, encoding?: string) => {
          this.executionContext.log('info', `Buffer.from called with ${data.substring(0, 20)}...`);
          return Buffer.from(data, encoding as BufferEncoding);
        }
      },
      process: {
        env: new Proxy({}, {
          get: (target, prop) => {
            const key = String(prop);
            this.executionContext.recordEvent('env_access', { key });
            return `MOCK_ENV_${key}`;
          }
        })
      },
      
      // Crypto
      crypto: this.createMockCrypto()
    };
    
    // Add global wrapper for JSON methods to detect serialization/deserialization
    sandbox.JSON = {
      parse: (text: string) => {
        this.executionContext.recordEvent('json_parse', { length: text.length });
        return JSON.parse(text);
      },
      stringify: (obj: any) => {
        this.executionContext.recordEvent('json_stringify', { type: typeof obj });
        return JSON.stringify(obj);
      }
    };
    
    // Add eval with monitoring
    sandbox.eval = (code: string) => {
      this.executionContext.recordEvent('eval', { code: code.substring(0, 50) });
      this.taintTracker.checkSinks('eval', code);
      return vm.runInContext(code, vm.createContext(sandbox));
    };
    
    return sandbox;
  }
  
  /**
   * Create a mock document object with instrumentation
   */
  private createMockDocument(): Record<string, any> {
    return {
      createElement: (tagName: string) => ({
        tagName,
        innerHTML: '',
        appendChild: () => {},
        setAttribute: (name: string, value: string) => {
          this.executionContext.recordEvent('dom_attribute', { tagName, name, value });
          this.taintTracker.checkSinks('dom', value);
        }
      }),
      getElementsByTagName: () => [],
      getElementById: () => null,
      querySelector: () => null,
      querySelectorAll: () => [],
      body: {
        appendChild: () => {},
        innerHTML: ''
      },
      cookie: {
        toString: () => 'mock-cookie=value',
        set: (value: string) => {
          this.executionContext.recordEvent('cookie_write', { value });
          this.taintTracker.checkSinks('cookie', value);
        }
      },
      location: {
        href: 'https://example.com',
        origin: 'https://example.com',
        toString: () => 'https://example.com'
      }
    };
  }
  
  /**
   * Create a mock storage object (localStorage/sessionStorage)
   */
  private createMockStorage(): Record<string, any> {
    const storage: Record<string, string> = {};
    return {
      getItem: (key: string) => {
        this.executionContext.recordEvent('storage_read', { key });
        return storage[key] || null;
      },
      setItem: (key: string, value: string) => {
        this.executionContext.recordEvent('storage_write', { key });
        this.taintTracker.checkSinks('storage', value);
        storage[key] = value;
      },
      removeItem: (key: string) => {
        this.executionContext.recordEvent('storage_delete', { key });
        delete storage[key];
      },
      clear: () => {
        this.executionContext.recordEvent('storage_clear', {});
        Object.keys(storage).forEach(key => delete storage[key]);
      }
    };
  }
  
  /**
   * Create a mock crypto object with instrumentation
   */
  private createMockCrypto(): Record<string, any> {
    return {
      subtle: {
        digest: (algorithm: string, data: ArrayBuffer) => {
          this.executionContext.recordEvent('crypto_digest', { algorithm });
          return Promise.resolve(new ArrayBuffer(32));
        },
        encrypt: (algorithm: any, key: any, data: ArrayBuffer) => {
          this.executionContext.recordEvent('crypto_encrypt', { algorithm: algorithm.name });
          return Promise.resolve(new ArrayBuffer(data.byteLength + 16));
        },
        decrypt: (algorithm: any, key: any, data: ArrayBuffer) => {
          this.executionContext.recordEvent('crypto_decrypt', { algorithm: algorithm.name });
          return Promise.resolve(new ArrayBuffer(data.byteLength - 16));
        },
        sign: (algorithm: any, key: any, data: ArrayBuffer) => {
          this.executionContext.recordEvent('crypto_sign', { algorithm: algorithm.name });
          return Promise.resolve(new ArrayBuffer(64));
        },
        verify: (algorithm: any, key: any, signature: ArrayBuffer, data: ArrayBuffer) => {
          this.executionContext.recordEvent('crypto_verify', { algorithm: algorithm.name });
          return Promise.resolve(true);
        }
      },
      getRandomValues: (array: Uint8Array) => {
        this.executionContext.recordEvent('crypto_random', { length: array.length });
        return array;
      }
    };
  }
  
  /**
   * Mock require to capture module usage
   */
  private mockRequire(moduleName: string): any {
    this.executionContext.recordEvent('require', { module: moduleName });
    
    // Mock commonly used modules
    switch (moduleName) {
      case 'fs':
        return this.mockFileSystem();
      case 'http':
      case 'https':
        return this.mockHttp();
      case 'child_process':
        return this.mockChildProcess();
      case 'path':
        return path;
      case 'crypto':
        return this.mockNodeCrypto();
      case 'express':
        return this.mockExpress();
      default:
        return {};
    }
  }
  
  /**
   * Mock Node.js file system module
   */
  private mockFileSystem(): Record<string, any> {
    return {
      readFile: (path: string, options: any, callback: Function) => {
        this.executionContext.recordFileAccess(path, 'read');
        this.taintTracker.checkSinks('file_path', path);
        
        if (typeof options === 'function') {
          callback = options;
        }
        
        callback(null, Buffer.from('Mock file content'));
      },
      readFileSync: (path: string) => {
        this.executionContext.recordFileAccess(path, 'read');
        this.taintTracker.checkSinks('file_path', path);
        return Buffer.from('Mock file content');
      },
      writeFile: (path: string, data: any, options: any, callback: Function) => {
        this.executionContext.recordFileAccess(path, 'write');
        this.taintTracker.checkSinks('file_path', path);
        this.taintTracker.checkSinks('file_data', data);
        
        if (typeof options === 'function') {
          callback = options;
        }
        
        callback(null);
      },
      writeFileSync: (path: string, data: any) => {
        this.executionContext.recordFileAccess(path, 'write');
        this.taintTracker.checkSinks('file_path', path);
        this.taintTracker.checkSinks('file_data', data);
      },
      existsSync: () => true,
      mkdirSync: () => {},
    };
  }
  
  /**
   * Mock Node.js HTTP/HTTPS modules
   */
  private mockHttp(): Record<string, any> {
    return {
      request: (url: string | any, options: any, callback: Function) => {
        if (typeof url === 'string') {
          this.executionContext.recordNetworkRequest(url, 'request');
          this.taintTracker.checkSinks('url', url);
        } else if (url.url) {
          this.executionContext.recordNetworkRequest(url.url, 'request');
          this.taintTracker.checkSinks('url', url.url);
        }
        
        return {
          on: () => {},
          write: () => {},
          end: () => {
            if (callback) {
              callback({
                on: (event: string, handler: Function) => {
                  if (event === 'data') {
                    handler(Buffer.from('Mock response data'));
                  } else if (event === 'end') {
                    handler();
                  }
                },
                statusCode: 200,
                headers: {}
              });
            }
          }
        };
      },
      get: (url: string, callback: Function) => {
        this.executionContext.recordNetworkRequest(url, 'get');
        this.taintTracker.checkSinks('url', url);
        
        callback({
          on: (event: string, handler: Function) => {
            if (event === 'data') {
              handler(Buffer.from('Mock response data'));
            } else if (event === 'end') {
              handler();
            }
          },
          statusCode: 200,
          headers: {}
        });
        
        return {
          on: () => {}
        };
      }
    };
  }
  
  /**
   * Mock Node.js child_process module
   */
  private mockChildProcess(): Record<string, any> {
    return {
      exec: (command: string, options: any, callback: Function) => {
        this.executionContext.recordCommandExecution(command);
        this.taintTracker.checkSinks('command', command);
        
        if (typeof options === 'function') {
          callback = options;
        }
        
        if (callback) {
          callback(null, 'Mock stdout', '');
        }
      },
      execSync: (command: string) => {
        this.executionContext.recordCommandExecution(command);
        this.taintTracker.checkSinks('command', command);
        return Buffer.from('Mock stdout');
      },
      spawn: () => ({
        stdout: {
          on: () => {}
        },
        stderr: {
          on: () => {}
        },
        on: () => {}
      }),
      fork: () => ({
        on: () => {}
      })
    };
  }
  
  /**
   * Mock Node.js crypto module
   */
  private mockNodeCrypto(): Record<string, any> {
    return {
      createHash: (algorithm: string) => {
        this.executionContext.log('info', `Crypto hash algorithm: ${algorithm}`);
        
        // Check for weak hash algorithms
        if (['md5', 'sha1'].includes(algorithm.toLowerCase())) {
          this.executionContext.recordVulnerability({
            ruleId: 'dynamic-crypto-001',
            severity: 'high',
            message: `Weak cryptographic hash algorithm detected: ${algorithm}`,
            line: 0,
            column: 0,
            file: 'dynamic-analysis',
            remediation: `Replace ${algorithm} with a stronger algorithm like SHA-256 or SHA-3`
          });
        }
        
        return {
          update: (data: any) => {
            return {
              digest: (encoding: string) => 'mockhash'
            };
          }
        };
      },
      randomBytes: (size: number) => {
        this.executionContext.log('info', `Crypto random bytes: ${size}`);
        return Buffer.alloc(size);
      },
      createCipheriv: (algorithm: string) => {
        this.executionContext.log('info', `Crypto cipher algorithm: ${algorithm}`);
        return {
          update: () => Buffer.alloc(10),
          final: () => Buffer.alloc(10)
        };
      },
      createDecipheriv: (algorithm: string) => {
        this.executionContext.log('info', `Crypto decipher algorithm: ${algorithm}`);
        return {
          update: () => Buffer.alloc(10),
          final: () => Buffer.alloc(10)
        };
      }
    };
  }
  
  /**
   * Mock Express.js framework
   */
  private mockExpress(): Record<string, any> {
    const app = () => {};
    
    app.get = (path: string, handler: Function) => {
      this.executionContext.log('info', `Express route registered: GET ${path}`);
    };
    
    app.post = (path: string, handler: Function) => {
      this.executionContext.log('info', `Express route registered: POST ${path}`);
    };
    
    app.use = () => {};
    
    return () => app;
  }
  
  /**
   * Run all test cases in the sandbox and collect vulnerabilities
   */
  private async runTestCases(testCases: TestCase[], sandbox: Record<string, any>): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Reset state before each test
    this.executionContext.reset();
    this.taintTracker.reset();
    
    // Run each test case
    for (const test of testCases) {
      try {
        // Create a function that will use the test input
        const testFunction = `
          function runDynamicTest(input) {
            // This function will be different based on the test case
            // but will use the input in a way that might trigger the vulnerability
            let result;
            
            try {
              // Different sink functions based on vulnerability type
              if (input.includes("'") || input.includes("--")) {
                // SQL injection test
                result = executeSql("SELECT * FROM users WHERE name = '" + input + "'");
              } else if (input.includes("<") || input.includes(">")) {
                // XSS test
                document.body.innerHTML = input;
              } else if (input.includes(";") || input.includes("|")) {
                // Command injection test
                require('child_process').execSync(input);
              } else if (input.includes("..") || input.includes("/etc")) {
                // Path traversal test
                require('fs').readFileSync(input);
              } else if (input.includes("http:") || input.includes("file:")) {
                // SSRF test
                require('http').get(input);
              } else {
                // Generic test
                eval(input);
              }
            } catch (e) {
              // Expected to throw for malicious input
            }
            
            return result;
          }
          
          // Mock functions for tests
          function executeSql(query) {
            __executionContext.recordEvent('sql_query', { query });
            __taintTracker.checkSinks('sql', query);
            return { rows: [] };
          }
          
          // Run the test with the payload
          runDynamicTest(${JSON.stringify(test.input)});
        `;
        
        // Run test code in sandbox
        vm.runInContext(testFunction, vm.createContext(sandbox));
        
        // Check for detected vulnerabilities
        const detectedVulnerabilities = [
          ...this.taintTracker.getVulnerabilities(),
          ...this.executionContext.getVulnerabilities()
        ];
        
        if (detectedVulnerabilities.length > 0) {
          // Add them to the collected vulnerabilities
          vulnerabilities.push(...detectedVulnerabilities);
        }
      } catch (error) {
        console.error(`Error running test case ${test.name}:`, error);
      }
    }
    
    return vulnerabilities;
  }
  
  /**
   * Run a specific program using the appropriate runtime
   * For non-JavaScript code, this would call out to external processes
   */
  public async analyzeProgram(code: string, language: SupportedLanguage, staticVulnerabilities: Vulnerability[]): Promise<Vulnerability[]> {
    switch (language) {
      case 'javascript':
        return this.analyzeJavaScript(code, staticVulnerabilities);
      case 'python':
        return this.analyzePython(code, staticVulnerabilities);
      case 'java':
        return this.analyzeJava(code, staticVulnerabilities);
      case 'csharp':
        return this.analyzeCSharp(code, staticVulnerabilities);
      default:
        return [];
    }
  }
  
  /**
   * Write code to temp file and execute it with Python
   * This would normally use child_process to execute but is mocked for now
   */
  private async analyzePython(code: string, staticVulnerabilities: Vulnerability[]): Promise<Vulnerability[]> {
    // This would execute Python with instrumentation in a real implementation
    console.log("Python analysis is simulated - would execute Python interpreter");
    return [];
  }
  
  /**
   * Write code to temp file and execute with Java
   * This would normally use child_process to execute but is mocked for now
   */
  private async analyzeJava(code: string, staticVulnerabilities: Vulnerability[]): Promise<Vulnerability[]> {
    // This would compile and execute Java with instrumentation in a real implementation
    console.log("Java analysis is simulated - would execute Java compiler and runtime");
    return [];
  }
  
  /**
   * Write code to temp file and execute with C#
   * This would normally use child_process to execute but is mocked for now
   */
  private async analyzeCSharp(code: string, staticVulnerabilities: Vulnerability[]): Promise<Vulnerability[]> {
    // This would compile and execute C# with instrumentation in a real implementation
    console.log("C# analysis is simulated - would execute C# compiler and runtime");
    return [];
  }
} 