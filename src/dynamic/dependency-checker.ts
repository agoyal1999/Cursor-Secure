import * as fs from 'fs';
import * as path from 'path';
import { SupportedLanguage, Vulnerability } from '../interfaces';

/**
 * A class to check dependencies for known vulnerabilities
 */
export class DependencyChecker {
  // Common vulnerable package versions
  private knownVulnerabilities: Record<string, Record<string, string[]>> = {
    'javascript': {
      'lodash': ['<4.17.20', 'Prototype pollution vulnerability in merge/set functions'],
      'express': ['<4.17.3', 'Various security vulnerabilities including ReDOS'],
      'minimist': ['<1.2.6', 'Prototype pollution vulnerability'],
      'jquery': ['<3.5.0', 'XSS vulnerability in jQuery.htmlPrefilter()'],
      'node-fetch': ['<2.6.7', 'Exposure of system resource through allocation of excessive resources'],
      'serialize-javascript': ['<3.1.0', 'Remote code execution vulnerability'],
      'ws': ['<7.4.6', 'ReDoS vulnerability in the permessage-deflate extension']
    },
    'python': {
      'django': ['<3.2.13', 'Multiple security vulnerabilities including SQL injection'],
      'flask': ['<2.0.0', 'Open redirect vulnerability'],
      'requests': ['<2.26.0', 'CRLF injection vulnerability'],
      'cryptography': ['<36.0.0', 'Memory corruption vulnerability'],
      'pyjwt': ['<2.0.0', 'Authentication bypass vulnerability'],
      'pillow': ['<9.0.0', 'Multiple security vulnerabilities including buffer overflow']
    },
    'java': {
      'log4j-core': ['<2.15.0', 'Remote code execution vulnerability (Log4Shell)'],
      'spring-core': ['<5.3.20', 'Remote code execution vulnerability (Spring4Shell)'],
      'apache-struts2-core': ['<2.5.30', 'Multiple RCE vulnerabilities'],
      'jackson-databind': ['<2.13.2', 'Deserialization vulnerability']
    },
    'csharp': {
      'Newtonsoft.Json': ['<13.0.1', 'Deserialization vulnerability'],
      'Microsoft.Data.SqlClient': ['<3.0.0', 'SQL injection vulnerability'],
      'System.Text.Encodings.Web': ['<5.0.1', 'XSS vulnerability']
    }
  };

  /**
   * Checks a codebase for known vulnerable dependencies
   */
  public check(filepath: string, language: SupportedLanguage): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    
    // Determine which dependency file to check based on language
    let dependencyFile = this.getDependencyFilePath(filepath, language);
    
    if (!dependencyFile || !fs.existsSync(dependencyFile)) {
      return vulnerabilities;
    }
    
    // Read and parse the dependency file
    try {
      const dependenciesMap = this.parseDependencyFile(dependencyFile, language);
      
      // Check each dependency against known vulnerabilities
      for (const [packageName, version] of Object.entries(dependenciesMap)) {
        const vulns = this.checkDependency(packageName, version, language);
        vulnerabilities.push(...vulns);
      }
    } catch (error) {
      console.error(`Error checking dependencies: ${error}`);
    }
    
    return vulnerabilities;
  }
  
  /**
   * Gets the appropriate dependency file path based on language
   */
  private getDependencyFilePath(filepath: string, language: SupportedLanguage): string | null {
    const dir = path.dirname(filepath);
    
    switch (language) {
      case 'javascript':
        return this.findFileUpwards('package.json', dir);
      case 'python':
        return this.findFileUpwards(['requirements.txt', 'Pipfile', 'pyproject.toml'], dir);
      case 'java':
        return this.findFileUpwards(['pom.xml', 'build.gradle'], dir);
      case 'csharp':
        return this.findFileUpwards(['*.csproj', 'packages.config'], dir);
      default:
        return null;
    }
  }
  
  /**
   * Find a file by traversing directories upwards until found
   */
  private findFileUpwards(filenames: string | string[], dir: string): string | null {
    const filenamesToCheck = Array.isArray(filenames) ? filenames : [filenames];
    
    let currentDir = dir;
    while (currentDir !== path.parse(currentDir).root) {
      for (const filename of filenamesToCheck) {
        if (filename.includes('*')) {
          // Handle glob patterns (simplified)
          const pattern = filename.replace('*', '');
          const files = fs.readdirSync(currentDir);
          const match = files.find(f => f.endsWith(pattern));
          if (match) {
            return path.join(currentDir, match);
          }
        } else {
          const filePath = path.join(currentDir, filename);
          if (fs.existsSync(filePath)) {
            return filePath;
          }
        }
      }
      // Go up one directory
      currentDir = path.dirname(currentDir);
    }
    
    return null;
  }
  
  /**
   * Parse the dependency file to extract package versions
   */
  private parseDependencyFile(filePath: string, language: SupportedLanguage): Record<string, string> {
    const dependencies: Record<string, string> = {};
    const content = fs.readFileSync(filePath, 'utf8');
    
    switch (language) {
      case 'javascript':
        try {
          const packageJson = JSON.parse(content);
          Object.assign(dependencies, packageJson.dependencies || {});
          Object.assign(dependencies, packageJson.devDependencies || {});
        } catch (e) {
          console.error(`Error parsing package.json: ${e}`);
        }
        break;
        
      case 'python':
        if (filePath.endsWith('requirements.txt')) {
          // Parse requirements.txt format (simplified)
          const lines = content.split('\n');
          for (const line of lines) {
            const match = line.match(/^([a-zA-Z0-9_-]+)[=~<>!]{1,2}(.+)$/);
            if (match) {
              dependencies[match[1]] = match[2];
            }
          }
        } else if (filePath.endsWith('Pipfile')) {
          // Simplified Pipfile parsing
          const lines = content.split('\n');
          let inPackagesSection = false;
          for (const line of lines) {
            if (line.trim() === '[packages]') {
              inPackagesSection = true;
              continue;
            }
            if (inPackagesSection && line.includes('=')) {
              const [name, version] = line.split('=').map(s => s.trim());
              if (name && version) {
                dependencies[name.replace(/['"]/g, '')] = version.replace(/['"]/g, '');
              }
            }
          }
        }
        break;
        
      case 'java':
        if (filePath.endsWith('pom.xml')) {
          // Simplified XML parsing for Maven
          const matches = content.match(/<dependency>[\s\S]*?<artifactId>(.*?)<\/artifactId>[\s\S]*?<version>(.*?)<\/version>[\s\S]*?<\/dependency>/g) || [];
          for (const match of matches) {
            const artifactId = match.match(/<artifactId>(.*?)<\/artifactId>/)?.[1];
            const version = match.match(/<version>(.*?)<\/version>/)?.[1];
            if (artifactId && version) {
              dependencies[artifactId] = version;
            }
          }
        }
        break;
        
      case 'csharp':
        if (filePath.endsWith('.csproj')) {
          // Simplified XML parsing for .NET
          const matches = content.match(/<PackageReference Include="(.*?)" Version="(.*?)" \/>/g) || [];
          for (const match of matches) {
            const packageMatch = match.match(/Include="(.*?)"/);
            const versionMatch = match.match(/Version="(.*?)"/);
            if (packageMatch && versionMatch) {
              dependencies[packageMatch[1]] = versionMatch[1];
            }
          }
        }
        break;
    }
    
    return dependencies;
  }
  
  /**
   * Check if a specific dependency is vulnerable
   */
  private checkDependency(packageName: string, version: string, language: SupportedLanguage): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const knownVulns = this.knownVulnerabilities[language][packageName];
    
    if (!knownVulns) {
      return vulnerabilities;
    }
    
    // For simplicity, we're just doing basic version string comparison
    // A more robust solution would use semver comparison
    for (let i = 0; i < knownVulns.length; i += 2) {
      const vulnerableVersionPattern = knownVulns[i];
      const description = knownVulns[i + 1];
      
      if (this.isVersionVulnerable(version, vulnerableVersionPattern)) {
        vulnerabilities.push({
          ruleId: `dep-${language}-${packageName.replace(/[^a-zA-Z0-9]/g, '-')}`,
          message: `Vulnerable dependency: ${packageName} version ${version} has known security issues: ${description}`,
          severity: 'high',
          line: 0,
          column: 0,
          file: 'dependency-check',
          remediation: `Update ${packageName} to a newer version`
        });
      }
    }
    
    return vulnerabilities;
  }
  
  /**
   * Check if a version matches a vulnerable version pattern
   * This is a simplified implementation - a real-world solution would use semver
   */
  private isVersionVulnerable(version: string, pattern: string): boolean {
    // Remove leading characters like ^ or ~ from the version string
    version = version.replace(/^[~^]/, '');
    
    // Handle patterns like <2.0.0
    if (pattern.startsWith('<')) {
      const patternVersion = pattern.substring(1);
      return this.compareVersions(version, patternVersion) < 0;
    }
    
    // Handle patterns like <=2.0.0
    if (pattern.startsWith('<=')) {
      const patternVersion = pattern.substring(2);
      return this.compareVersions(version, patternVersion) <= 0;
    }
    
    // Handle exact versions
    return version === pattern;
  }
  
  /**
   * Simple version comparison
   * Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
   */
  private compareVersions(v1: string, v2: string): number {
    // Handle versions with suffixes like "-alpha", "-beta", etc.
    const hasSuffix1 = v1.includes('-');
    const hasSuffix2 = v2.includes('-');
    
    // If only one has a suffix, the one without is considered higher
    if (hasSuffix1 && !hasSuffix2) return -1;
    if (!hasSuffix1 && hasSuffix2) return 1;
    
    // Extract the numeric parts
    const numericPart1 = hasSuffix1 ? v1.split('-')[0] : v1;
    const numericPart2 = hasSuffix2 ? v2.split('-')[0] : v2;
    
    const parts1 = numericPart1.split('.').map(Number);
    const parts2 = numericPart2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const part1 = i < parts1.length ? parts1[i] : 0;
      const part2 = i < parts2.length ? parts2[i] : 0;
      
      if (part1 < part2) return -1;
      if (part1 > part2) return 1;
    }
    
    // If numeric parts are equal but both have suffixes, compare them
    if (hasSuffix1 && hasSuffix2) {
      const suffix1 = v1.split('-')[1];
      const suffix2 = v2.split('-')[1];
      
      // Simple string comparison for suffixes
      if (suffix1 < suffix2) return -1;
      if (suffix1 > suffix2) return 1;
    }
    
    return 0;
  }
} 