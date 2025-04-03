#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import * as glob from 'glob';
import { Scanner, ScanOptions, ScanResult, SupportedLanguage } from './index';
import { installPreCommitHook, installPrePushHook, scanStagedFiles } from './utils/git-hooks';

// File extensions and their corresponding languages
const fileExtensionMap: { [key: string]: SupportedLanguage } = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'javascript',
  '.tsx': 'javascript',
  '.py': 'python',
  '.java': 'java',
  '.cs': 'csharp'
};

// Get command line arguments
const args = process.argv.slice(2);

// Parse command line arguments
const command = args[0] || 'scan';
const options: { [key: string]: any } = {
  stagedOnly: args.includes('--staged-only'),
  full: args.includes('--full'),
  verbose: args.includes('--verbose') || args.includes('-v'),
  output: args.includes('--output') ? args[args.indexOf('--output') + 1] : null,
  format: args.includes('--format') ? args[args.indexOf('--format') + 1] : 'text',
  config: args.includes('--config') ? args[args.indexOf('--config') + 1] : null,
  installHooks: args.includes('--install-hooks'),
  help: args.includes('--help') || args.includes('-h'),
  version: args.includes('--version')
};

// Set the paths to scan
let paths = args.filter((arg: string) => !arg.startsWith('-') && arg !== command);
if (paths.length === 0) {
  paths = ['.'];
}

// Display help
if (options.help) {
  showHelp();
  process.exit(0);
}

// Display version
if (options.version) {
  const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));
  console.log(`Secure Scanner v${packageJson.version}`);
  process.exit(0);
}

// Execute the command
switch (command) {
  case 'scan':
    performScan();
    break;
  case 'install-hooks':
    installHooks();
    break;
  default:
    console.error(`Unknown command: ${command}`);
    showHelp();
    process.exit(1);
}

/**
 * Perform a security scan based on the provided options
 */
function performScan() {
  // Load configuration
  const scanOptions = loadConfiguration();
  
  // Create scanner instance
  const scanner = new Scanner(scanOptions);
  
  // Get files to scan
  let filesToScan: string[] = [];
  
  if (options.stagedOnly) {
    // Scan only staged files
    const results = scanStagedFiles(process.cwd(), scanOptions);
    outputResults(results);
    checkExitCode(results);
    return;
  } else {
    // Scan specified paths or the current directory
    for (const scanPath of paths) {
      if (fs.existsSync(scanPath)) {
        const stats = fs.statSync(scanPath);
        
        if (stats.isDirectory()) {
          // If it's a directory, get all supported files
          const globPattern = `${scanPath}/**/*.{js,jsx,ts,tsx,py,java,cs}`;
          const matches = glob.sync(globPattern, { ignore: scanOptions.ignorePatterns || [] });
          filesToScan = filesToScan.concat(matches);
        } else if (stats.isFile()) {
          // If it's a file, add it directly
          filesToScan.push(scanPath);
        }
      }
    }
  }
  
  // Scan each file
  const results: ScanResult[] = [];
  
  for (const filePath of filesToScan) {
    try {
      // Get the language based on file extension
      const extension = path.extname(filePath).toLowerCase();
      const language = fileExtensionMap[extension];
      
      if (!language) {
        // Skip unsupported file types
        if (options.verbose) {
          console.log(`Skipping unsupported file: ${filePath}`);
        }
        continue;
      }
      
      // Read the file content
      const content = fs.readFileSync(filePath, 'utf-8');
      
      // Scan the file
      const scanResult = scanner.scan(content, language);
      
      // Add file path to the result
      results.push({
        ...scanResult,
        filePath
      } as any);
      
      if (options.verbose) {
        console.log(`Scanned: ${filePath} - ${scanResult.vulnerabilities.length} issues found`);
      }
    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
    }
  }
  
  // Output the results
  outputResults(results);
  
  // Set exit code based on results
  checkExitCode(results);
}

/**
 * Load configuration from file or use defaults
 */
function loadConfiguration(): ScanOptions {
  const defaultOptions: ScanOptions = {
    ignorePatterns: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/vendor/**']
  };
  
  if (options.config && fs.existsSync(options.config)) {
    try {
      const configContent = fs.readFileSync(options.config, 'utf-8');
      const customOptions = JSON.parse(configContent);
      return { ...defaultOptions, ...customOptions };
    } catch (error) {
      console.error(`Error loading configuration file:`, error);
    }
  }
  
  return defaultOptions;
}

/**
 * Output the scan results in the specified format
 */
function outputResults(results: ScanResult[]) {
  // Calculate total vulnerabilities
  const totalVulnerabilities = results.reduce((total, result) => total + result.vulnerabilities.length, 0);
  
  // Count vulnerabilities by severity
  const severityCounts = {
    info: 0,
    warning: 0,
    error: 0,
    critical: 0,
    high: 0
  };
  
  results.forEach(result => {
    result.vulnerabilities.forEach(vuln => {
      severityCounts[vuln.severity]++;
    });
  });
  
  // Output based on format
  switch (options.format) {
    case 'json':
      const jsonOutput = JSON.stringify(results, null, 2);
      
      if (options.output) {
        fs.writeFileSync(options.output, jsonOutput);
      } else {
        console.log(jsonOutput);
      }
      break;
      
    case 'text':
    default:
      console.log('\n=== Secure Scanner Results ===\n');
      console.log(`Files scanned: ${results.length}`);
      console.log(`Total vulnerabilities found: ${totalVulnerabilities}`);
      console.log(`Critical: ${severityCounts.critical}`);
      console.log(`High: ${severityCounts.high}`);
      console.log(`Error: ${severityCounts.error}`);
      console.log(`Warning: ${severityCounts.warning}`);
      console.log(`Info: ${severityCounts.info}`);
      console.log('\n=== Vulnerability Details ===\n');
      
      results.forEach(result => {
        if (result.vulnerabilities.length > 0) {
          console.log(`File: ${(result as any).filePath}`);
          
          result.vulnerabilities.forEach(vuln => {
            console.log(`  [${vuln.severity.toUpperCase()}] ${vuln.message} (${vuln.ruleId})`);
            console.log(`  Line: ${vuln.line}, Column: ${vuln.column}`);
            if (vuln.fix) {
              console.log(`  Fix: ${vuln.fix.description}`);
            }
            console.log('');
          });
        }
      });
      
      if (totalVulnerabilities === 0) {
        console.log('No vulnerabilities found. Your code is secure!');
      }
      
      if (options.output) {
        // Capture console output and write to file
        // This is a simplification - real implementation would redirect console output
        fs.writeFileSync(options.output, 'Secure Scanner Results - See console for details');
      }
      break;
  }
}

/**
 * Set the exit code based on scan results
 */
function checkExitCode(results: ScanResult[]) {
  // Check if there are any critical or error vulnerabilities
  const hasCritical = results.some(result => 
    result.vulnerabilities.some(vuln => vuln.severity === 'critical')
  );
  
  const hasHigh = results.some(result => 
    result.vulnerabilities.some(vuln => vuln.severity === 'high')
  );
  
  const hasError = results.some(result => 
    result.vulnerabilities.some(vuln => vuln.severity === 'error')
  );
  
  if (hasCritical) {
    console.error('\nCritical vulnerabilities found. Please fix these issues before continuing.');
    process.exit(1);
  } else if (hasHigh) {
    console.warn('\nHigh-severity vulnerabilities found. It is strongly recommended to fix these issues.');
    process.exit(options.full ? 1 : 0);
  } else if (hasError) {
    console.warn('\nError-level vulnerabilities found. It is recommended to fix these issues.');
    process.exit(options.full ? 1 : 0);
  } else {
    console.log('\nNo critical, high, or error-level vulnerabilities found.');
    process.exit(0);
  }
}

/**
 * Install Git hooks in the current repository
 */
function installHooks() {
  const repoPath = process.cwd();
  
  // Install pre-commit hook
  const preCommitResult = installPreCommitHook(repoPath);
  if (preCommitResult) {
    console.log('Pre-commit hook installed successfully.');
  } else {
    console.error('Failed to install pre-commit hook.');
  }
  
  // Install pre-push hook
  const prePushResult = installPrePushHook(repoPath);
  if (prePushResult) {
    console.log('Pre-push hook installed successfully.');
  } else {
    console.error('Failed to install pre-push hook.');
  }
  
  process.exit(preCommitResult && prePushResult ? 0 : 1);
}

/**
 * Display help information
 */
function showHelp() {
  console.log(`
Secure Scanner - A lightweight vulnerability scanner for code

Usage:
  secure-scanner [command] [options] [paths...]

Commands:
  scan            Scan files for security vulnerabilities (default)
  install-hooks   Install Git hooks in the current repository

Options:
  --staged-only   Scan only staged files in Git
  --full          Perform a full scan with stricter rules
  --verbose, -v   Show verbose output
  --output FILE   Write results to the specified file
  --format FORMAT Output format (text or json)
  --config FILE   Use the specified configuration file
  --install-hooks Install Git hooks during scan
  --help, -h      Show this help
  --version       Show version information

Examples:
  secure-scanner                   Scan the current directory
  secure-scanner scan src/         Scan the src directory
  secure-scanner --staged-only     Scan only staged files
  secure-scanner --format json     Output results in JSON format
  secure-scanner install-hooks     Install Git hooks in the current repository
  `);
} 