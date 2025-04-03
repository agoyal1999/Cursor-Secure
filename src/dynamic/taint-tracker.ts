import { SupportedLanguage, Vulnerability } from '../interfaces';

// Define Severity type locally to avoid import errors
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'warning' | 'error';

// Define the ITaintTracker interface locally
interface ITaintTracker {
  instrumentCode(code: string, language: SupportedLanguage): string;
  markTainted(variableName: string, value: any): void;
  checkSinks(sinkType: string, value: any): void;
  getVulnerabilities(): Vulnerability[];
  reset(): void;
}

interface TaintSource {
  pattern: RegExp;
  name: string;
  description: string;
}

interface TaintSink {
  type: string;
  pattern: RegExp;
  severity: Severity;
  message: string;
}

export class TaintTracker implements ITaintTracker {
  private taintedData: Map<string, any> = new Map();
  private vulnerabilities: Vulnerability[] = [];
  
  // Common sources of untrusted data
  private sources: Record<SupportedLanguage, TaintSource[]> = {
    javascript: [
      { pattern: /req\.params\.(\w+)/g, name: 'URL parameter', description: 'URL parameter from request' },
      { pattern: /req\.query\.(\w+)/g, name: 'Query parameter', description: 'Query string parameter from request' },
      { pattern: /req\.body\.(\w+)/g, name: 'Request body', description: 'POST data from request body' },
      { pattern: /localStorage\.getItem\(['"](\w+)['"]\)/g, name: 'LocalStorage', description: 'Data from browser localStorage' },
      { pattern: /sessionStorage\.getItem\(['"](\w+)['"]\)/g, name: 'SessionStorage', description: 'Data from browser sessionStorage' },
      { pattern: /document\.cookie/g, name: 'Cookie', description: 'Browser cookie data' },
      { pattern: /location\.search/g, name: 'URL search', description: 'URL query string' },
      { pattern: /prompt\(.*\)/g, name: 'User prompt', description: 'Direct user input via prompt' }
    ],
    python: [
      { pattern: /request\.args\.get\(['"](\w+)['"]\)/g, name: 'URL parameter', description: 'Flask/Django URL parameter' },
      { pattern: /request\.POST\.get\(['"](\w+)['"]\)/g, name: 'POST data', description: 'Django POST data' },
      { pattern: /request\.GET\.get\(['"](\w+)['"]\)/g, name: 'GET data', description: 'Django GET data' },
      { pattern: /request\.form\.get\(['"](\w+)['"]\)/g, name: 'Form data', description: 'Flask form data' },
      { pattern: /input\(.*\)/g, name: 'User input', description: 'Direct user input via stdin' }
    ],
    java: [
      { pattern: /request\.getParameter\(['"](\w+)['"]\)/g, name: 'Request parameter', description: 'Servlet request parameter' },
      { pattern: /request\.getHeader\(['"](\w+)['"]\)/g, name: 'Request header', description: 'HTTP header from request' },
      { pattern: /request\.getInputStream\(\)/g, name: 'Request stream', description: 'Raw HTTP request data' }
    ],
    csharp: [
      { pattern: /Request\.QueryString\[['"](\w+)['"]\]/g, name: 'Query string', description: '.NET query string data' },
      { pattern: /Request\.Form\[['"](\w+)['"]\]/g, name: 'Form data', description: '.NET form data' },
      { pattern: /Request\.Params\[['"](\w+)['"]\]/g, name: 'Request parameters', description: '.NET request parameters' },
      { pattern: /Console\.ReadLine\(\)/g, name: 'Console input', description: 'Direct user input via console' }
    ]
  };
  
  // Common sinks where tainted data should not flow to
  private sinks: Record<SupportedLanguage, TaintSink[]> = {
    javascript: [
      { type: 'sql', pattern: /db\.query\((.*)\)/g, severity: 'high', message: 'SQL injection vulnerability: tainted data flows to database query' },
      { type: 'command', pattern: /exec\((.*)\)/g, severity: 'critical', message: 'Command injection vulnerability: tainted data flows to command execution' },
      { type: 'eval', pattern: /eval\((.*)\)/g, severity: 'critical', message: 'Code injection vulnerability: tainted data flows to eval' },
      { type: 'dom', pattern: /innerHTML\s*=\s*(.*)/g, severity: 'high', message: 'XSS vulnerability: tainted data flows to DOM element' },
      { type: 'file_path', pattern: /fs\.readFile\((.*)\)/g, severity: 'high', message: 'Path traversal vulnerability: tainted data flows to file system operation' },
      { type: 'url', pattern: /fetch\((.*)\)/g, severity: 'medium', message: 'SSRF vulnerability: tainted data flows to outbound request' }
    ],
    python: [
      { type: 'sql', pattern: /cursor\.execute\((.*)\)/g, severity: 'high', message: 'SQL injection vulnerability: tainted data flows to database query' },
      { type: 'command', pattern: /os\.system\((.*)\)/g, severity: 'critical', message: 'Command injection vulnerability: tainted data flows to command execution' },
      { type: 'eval', pattern: /eval\((.*)\)/g, severity: 'critical', message: 'Code injection vulnerability: tainted data flows to eval' },
      { type: 'file_path', pattern: /open\((.*)\)/g, severity: 'high', message: 'Path traversal vulnerability: tainted data flows to file operation' },
      { type: 'template', pattern: /render_template\((.*)\)/g, severity: 'medium', message: 'Template injection vulnerability: tainted data flows to template' }
    ],
    java: [
      { type: 'sql', pattern: /prepareStatement\((.*)\)/g, severity: 'high', message: 'SQL injection vulnerability: tainted data flows to SQL statement' },
      { type: 'command', pattern: /Runtime\.getRuntime\(\)\.exec\((.*)\)/g, severity: 'critical', message: 'Command injection vulnerability: tainted data flows to command execution' },
      { type: 'xpath', pattern: /xpath\.evaluate\((.*)\)/g, severity: 'medium', message: 'XPath injection vulnerability: tainted data flows to XPath query' },
      { type: 'file_path', pattern: /new File\((.*)\)/g, severity: 'high', message: 'Path traversal vulnerability: tainted data flows to file operation' }
    ],
    csharp: [
      { type: 'sql', pattern: /SqlCommand\((.*)\)/g, severity: 'high', message: 'SQL injection vulnerability: tainted data flows to SQL command' },
      { type: 'command', pattern: /Process\.Start\((.*)\)/g, severity: 'critical', message: 'Command injection vulnerability: tainted data flows to process execution' },
      { type: 'xpath', pattern: /XPathExpression\.Compile\((.*)\)/g, severity: 'medium', message: 'XPath injection vulnerability: tainted data flows to XPath expression' },
      { type: 'file_path', pattern: /File\.Open\((.*)\)/g, severity: 'high', message: 'Path traversal vulnerability: tainted data flows to file operation' },
      { type: 'deserialization', pattern: /BinaryFormatter\.Deserialize\((.*)\)/g, severity: 'high', message: 'Insecure deserialization vulnerability: tainted data flows to deserializer' }
    ]
  };
  
  /**
   * Instrument code with taint tracking
   */
  public instrumentCode(code: string, language: SupportedLanguage): string {
    if (language !== 'javascript') {
      // Currently only JavaScript instrumentation is supported
      return code;
    }
    
    let instrumentedCode = code;
    
    // Add taint tracking header
    instrumentedCode = `
// Instrumented with taint tracking
const __taintMap = new Map();
function __markTainted(name, value) {
  __taintMap.set(name, value);
  __taintTracker.markTainted(name, value);
  return value;
}
function __checkSink(type, value) {
  __taintTracker.checkSinks(type, value);
  return value;
}

${instrumentedCode}`;
    
    // Instrument sources with safer regex replacements
    for (const source of this.sources[language]) {
      instrumentedCode = instrumentedCode.replace(
        source.pattern,
        (match, group) => `__markTainted('${group || "unknown"}', ${match})`
      );
    }
    
    // Instrument sinks with safer regex replacements that produce valid JavaScript
    for (const sink of this.sinks[language]) {
      // Improved regex replacements that handle parentheses properly
      if (sink.type === 'dom') {
        instrumentedCode = instrumentedCode.replace(
          sink.pattern,
          (match, group) => match.replace(group, `__checkSink('${sink.type}', ${group})`)
        );
      } else if (sink.type === 'sql') {
        instrumentedCode = instrumentedCode.replace(
          sink.pattern,
          (match, group) => {
            // Replace only the part within the parentheses, not including the parentheses
            const parts = match.split(group);
            return `${parts[0]}__checkSink('${sink.type}', ${group})${parts[1]}`;
          }
        );
      } else {
        // General case
        instrumentedCode = instrumentedCode.replace(
          sink.pattern,
          (match, group) => {
            // Handle cases where group is inside a function call
            if (match.includes(`(${group})`)) {
              return match.replace(`(${group})`, `(__checkSink('${sink.type}', ${group}))`);
            } else {
              return match.replace(group, `__checkSink('${sink.type}', ${group})`);
            }
          }
        );
      }
    }
    
    return instrumentedCode;
  }
  
  /**
   * Mark data as tainted
   */
  public markTainted(variableName: string, value: any): void {
    this.taintedData.set(variableName, value);
  }
  
  /**
   * Check if tainted data is flowing to a sink
   */
  public checkSinks(sinkType: string, value: any): void {
    if (value === undefined || value === null) {
      return;
    }
    
    // Check if the value is tainted
    let isTainted = false;
    let sourceName = '';
    
    // If it's a string, check if it matches any tainted value
    if (typeof value === 'string') {
      for (const [name, taintedValue] of this.taintedData.entries()) {
        if (typeof taintedValue === 'string' && value.includes(taintedValue)) {
          isTainted = true;
          sourceName = name;
          break;
        }
      }
    } else {
      // For objects/arrays, check if it's a direct reference to a tainted value
      for (const [name, taintedValue] of this.taintedData.entries()) {
        if (value === taintedValue) {
          isTainted = true;
          sourceName = name;
          break;
        }
      }
    }
    
    if (isTainted) {
      // Find appropriate sink information
      let sink: TaintSink | undefined;
      
      for (const language of ['javascript', 'python', 'java', 'csharp'] as SupportedLanguage[]) {
        sink = this.sinks[language].find(s => s.type === sinkType);
        if (sink) break;
      }
      
      if (sink) {
        this.vulnerabilities.push({
          ruleId: `taint-${sinkType}-001`,
          severity: sink.severity,
          message: `${sink.message} (source: ${sourceName})`,
          line: 0,
          column: 0,
          file: 'taint-analysis',
          remediation: `Sanitize all data coming from ${sourceName} before using it in ${sinkType} operations`
        });
      }
    }
  }
  
  /**
   * Get all detected vulnerabilities
   */
  public getVulnerabilities(): Vulnerability[] {
    return [...this.vulnerabilities];
  }
  
  /**
   * Reset the taint tracker state
   */
  public reset(): void {
    this.taintedData.clear();
    this.vulnerabilities = [];
  }
} 