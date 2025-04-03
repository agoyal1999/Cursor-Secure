import * as fs from 'fs';
import * as path from 'path';
import * as childProcess from 'child_process';
import { Scanner, ScanOptions, ScanResult, SupportedLanguage } from '../index';

// File extensions and their corresponding languages
const fileExtensionMap: { [key: string]: SupportedLanguage } = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'javascript', // Treat TypeScript as JavaScript for now
  '.tsx': 'javascript',
  '.py': 'python',
  '.java': 'java',
  '.cs': 'csharp'
};

/**
 * Creates a pre-commit hook in a Git repository
 */
export function installPreCommitHook(repoPath: string): boolean {
  try {
    const gitHooksPath = path.join(repoPath, '.git', 'hooks');
    const preCommitPath = path.join(gitHooksPath, 'pre-commit');
    
    // Create the hooks directory if it doesn't exist
    if (!fs.existsSync(gitHooksPath)) {
      fs.mkdirSync(gitHooksPath, { recursive: true });
    }
    
    // Create the pre-commit hook script
    const hookScript = `#!/bin/sh
# Secure Scanner pre-commit hook
# This hook scans staged files for security vulnerabilities
echo "Secure Scanner: Scanning staged files for security vulnerabilities..."
npx secure-scanner scan --staged-only
if [ $? -ne 0 ]; then
  echo "Secure Scanner: Critical security vulnerabilities detected. Commit aborted."
  echo "Please fix the issues and try again, or use --no-verify to bypass this check."
  exit 1
fi
`;
    
    // Write the hook script to the file
    fs.writeFileSync(preCommitPath, hookScript);
    
    // Make the hook script executable
    fs.chmodSync(preCommitPath, '755');
    
    return true;
  } catch (error) {
    console.error('Error installing pre-commit hook:', error);
    return false;
  }
}

/**
 * Creates a pre-push hook in a Git repository
 */
export function installPrePushHook(repoPath: string): boolean {
  try {
    const gitHooksPath = path.join(repoPath, '.git', 'hooks');
    const prePushPath = path.join(gitHooksPath, 'pre-push');
    
    // Create the hooks directory if it doesn't exist
    if (!fs.existsSync(gitHooksPath)) {
      fs.mkdirSync(gitHooksPath, { recursive: true });
    }
    
    // Create the pre-push hook script
    const hookScript = `#!/bin/sh
# Secure Scanner pre-push hook
# This hook scans the code for security vulnerabilities before pushing
echo "Secure Scanner: Scanning code for security vulnerabilities before pushing..."
npx secure-scanner scan --full
if [ $? -ne 0 ]; then
  echo "Secure Scanner: Critical security vulnerabilities detected. Push aborted."
  echo "Please fix the issues and try again, or use --no-verify to bypass this check."
  exit 1
fi
`;
    
    // Write the hook script to the file
    fs.writeFileSync(prePushPath, hookScript);
    
    // Make the hook script executable
    fs.chmodSync(prePushPath, '755');
    
    return true;
  } catch (error) {
    console.error('Error installing pre-push hook:', error);
    return false;
  }
}

/**
 * Gets the list of staged files in a Git repository
 */
export function getStagedFiles(repoPath: string): string[] {
  try {
    // Get the staged files using git diff
    const command = 'git diff --cached --name-only --diff-filter=ACMR';
    const result = childProcess.execSync(command, { cwd: repoPath }).toString();
    
    // Split the result by newline to get individual file paths
    return result.split('\n').filter(Boolean);
  } catch (error) {
    console.error('Error getting staged files:', error);
    return [];
  }
}

/**
 * Scans staged files for security vulnerabilities
 */
export function scanStagedFiles(repoPath: string, options: ScanOptions = {}): ScanResult[] {
  const stagedFiles = getStagedFiles(repoPath);
  const results: ScanResult[] = [];
  
  // Create a scanner instance
  const scanner = new Scanner(options);
  
  // Scan each staged file
  for (const filePath of stagedFiles) {
    const fullPath = path.join(repoPath, filePath);
    const extension = path.extname(filePath).toLowerCase();
    
    // Check if the file has a supported language extension
    const language = fileExtensionMap[extension];
    if (!language) {
      continue;
    }
    
    try {
      // Read the file content
      const content = fs.readFileSync(fullPath, 'utf-8');
      
      // Scan the file
      const result = scanner.scan(content, language);
      
      // Add the file path to the result
      results.push({
        ...result,
        filePath
      } as ScanResult);
    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
    }
  }
  
  return results;
} 