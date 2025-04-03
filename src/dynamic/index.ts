import { SupportedLanguage, Vulnerability } from '../interfaces';
import { ExecutionContext } from './context';
import { TaintTracker } from './taint-tracker';
import { TestGenerator } from './test-generator';
import { RuntimeAnalyzer } from './runtime-analyzer';
import { DependencyChecker } from './dependency-checker';
import { SecurityAuditor } from './security-auditor';
import { DynamicAnalyzer } from './analyzer';

// Export all components
export {
  ExecutionContext,
  TaintTracker,
  TestGenerator,
  RuntimeAnalyzer,
  DependencyChecker,
  SecurityAuditor,
  DynamicAnalyzer
};

/**
 * Analyze code dynamically for security vulnerabilities
 */
export async function analyzeDynamically(
  code: string,
  language: SupportedLanguage,
  staticVulnerabilities: Vulnerability[] = []
): Promise<Vulnerability[]> {
  try {
    const analyzer = new DynamicAnalyzer();
    // Pass a default filename and analyze the code
    const dynamicVulnerabilities = analyzer.analyze(code, language, 'dynamic-analysis.js');
    
    // Ensure all static vulnerabilities have the required file property
    const processedStaticVulns = staticVulnerabilities.map(vuln => {
      if (!vuln.file) {
        return { ...vuln, file: 'unknown-file' };
      }
      return vuln;
    });
    
    // Type assertion for the combined results
    return dynamicVulnerabilities.concat(processedStaticVulns as Vulnerability[]);
  } catch (error) {
    console.error('Error during dynamic analysis:', error);
    
    // Ensure all static vulnerabilities have the required file property
    const processedStaticVulns = staticVulnerabilities.map(vuln => {
      if (!vuln.file) {
        return { ...vuln, file: 'unknown-file' };
      }
      return vuln;
    });
    
    return processedStaticVulns as Vulnerability[];
  }
} 