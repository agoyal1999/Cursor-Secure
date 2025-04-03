import * as vscode from 'vscode';
import { Scanner } from '../../../src/scanner';
import { ScanOptions, ScanResult, SupportedLanguage } from '../../../src/interfaces';

// Map VS Code language IDs to our supported languages
const languageMap: { [key: string]: SupportedLanguage } = {
  'javascript': 'javascript',
  'typescript': 'javascript', // We'll treat TypeScript as JavaScript for now
  'python': 'python',
  'java': 'java',
  'csharp': 'csharp'
};

// Create a diagnostics collection
let diagnosticCollection: vscode.DiagnosticCollection;

// Create scanner instance
let scanner: Scanner;

// Extension activation
export function activate(context: vscode.ExtensionContext) {
  console.log('Secure Scanner extension is now active');
  
  // Initialize the diagnostics collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection('secureScanner');
  context.subscriptions.push(diagnosticCollection);
  
  // Initialize the scanner
  const scanOptions: ScanOptions = {
    ignorePatterns: getIgnorePatterns()
  };
  scanner = new Scanner(scanOptions);
  
  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('secure-scanner.scan', () => {
      scanCurrentDocument();
    })
  );
  
  context.subscriptions.push(
    vscode.commands.registerCommand('secure-scanner.scanProject', () => {
      scanWorkspace();
    })
  );
  
  // Register event handlers for real-time scanning
  if (getConfiguration().get('enableRealTimeScanning')) {
    // Scan on document open
    context.subscriptions.push(
      vscode.workspace.onDidOpenTextDocument(document => {
        scanDocument(document);
      })
    );
    
    // Scan on document save
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(document => {
        scanDocument(document);
      })
    );
    
    // Scan on document change (debounced)
    let changeTimeout: NodeJS.Timeout | null = null;
    context.subscriptions.push(
      vscode.workspace.onDidChangeTextDocument(event => {
        if (changeTimeout) {
          clearTimeout(changeTimeout);
        }
        
        changeTimeout = setTimeout(() => {
          scanDocument(event.document);
          changeTimeout = null;
        }, 500); // 500ms debounce
      })
    );
  }
  
  // Scan all open documents on startup
  vscode.workspace.textDocuments.forEach(document => {
    scanDocument(document);
  });
}

// Scan the current active document
function scanCurrentDocument() {
  const editor = vscode.window.activeTextEditor;
  if (editor) {
    scanDocument(editor.document);
  }
}

// Scan the entire workspace
async function scanWorkspace() {
  // Show progress indicator
  vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'Scanning workspace for security vulnerabilities',
    cancellable: true
  }, async (progress, token) => {
    // Clear previous diagnostics
    diagnosticCollection.clear();
    
    // Get all files in the workspace
    const files = await vscode.workspace.findFiles(
      '{**/*.js,**/*.ts,**/*.jsx,**/*.tsx,**/*.py,**/*.java,**/*.cs}',
      '{**/node_modules/**,**/dist/**,**/build/**}'
    );
    
    // Calculate total files for progress reporting
    const total = files.length;
    let processed = 0;
    
    // Scan each file
    for (const file of files) {
      if (token.isCancellationRequested) {
        break;
      }
      
      try {
        // Read the file content
        const document = await vscode.workspace.openTextDocument(file);
        scanDocument(document);
        
        // Update progress
        processed++;
        const increment = processed / total * 100;
        progress.report({ 
          increment, 
          message: `Scanned ${processed} of ${total} files (${file.fsPath})`
        });
      } catch (error) {
        console.error(`Error scanning file ${file.fsPath}:`, error);
      }
    }
    
    // Show summary
    const message = `Scan complete. Scanned ${processed} files.`;
    vscode.window.showInformationMessage(message);
  });
}

// Scan a document for security vulnerabilities
function scanDocument(document: vscode.TextDocument) {
  // Check if the document is supported
  const language = getLanguageForDocument(document);
  if (!language) {
    return;
  }
  
  // Get the document text
  const text = document.getText();
  
  // Scan the document
  const scanResult = scanner.scan(text, language);
  
  // Convert vulnerabilities to diagnostics
  const diagnostics = vulnerabilitiesToDiagnostics(scanResult, document);
  
  // Update diagnostics
  diagnosticCollection.set(document.uri, diagnostics);
}

// Convert scanner results to VS Code diagnostics
function vulnerabilitiesToDiagnostics(scanResult: ScanResult, document: vscode.TextDocument): vscode.Diagnostic[] {
  return scanResult.vulnerabilities.map(vuln => {
    // Get the range for the vulnerability
    const startPosition = vuln.line > 0 ? vuln.line - 1 : 0;
    const startChar = vuln.column > 0 ? vuln.column - 1 : 0;
    
    const endPosition = vuln.endLine ? vuln.endLine - 1 : startPosition;
    const endChar = vuln.endColumn ? vuln.endColumn - 1 : document.lineAt(startPosition).text.length;
    
    const range = new vscode.Range(startPosition, startChar, endPosition, endChar);
    
    // Create diagnostic with appropriate severity
    const diagnostic = new vscode.Diagnostic(
      range,
      `${vuln.message} (${vuln.ruleId})`,
      getSeverity(vuln.severity)
    );
    
    // Set source and code
    diagnostic.source = 'Secure Scanner';
    diagnostic.code = vuln.ruleId;
    
    return diagnostic;
  });
}

// Helper to get VS Code diagnostic severity from our severity
function getSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical':
    case 'error':
      return vscode.DiagnosticSeverity.Error;
    case 'warning':
      return vscode.DiagnosticSeverity.Warning;
    case 'info':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

// Get the language for a document
function getLanguageForDocument(document: vscode.TextDocument): SupportedLanguage | undefined {
  const vscodeLangId = document.languageId;
  return languageMap[vscodeLangId];
}

// Get configuration
function getConfiguration(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('secureScanner');
}

// Get ignore patterns from configuration
function getIgnorePatterns(): string[] {
  const config = getConfiguration();
  return config.get<string[]>('ignorePatterns') || [];
}

// Extension deactivation
export function deactivate() {
  // Clean up resources
  if (diagnosticCollection) {
    diagnosticCollection.clear();
    diagnosticCollection.dispose();
  }
} 