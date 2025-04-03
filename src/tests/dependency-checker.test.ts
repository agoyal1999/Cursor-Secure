import * as fs from 'fs';
import * as path from 'path';
import { DependencyChecker } from '../dynamic/dependency-checker';
import { SupportedLanguage } from '../interfaces';

// Mock fs module
jest.mock('fs', () => ({
  existsSync: jest.fn(),
  readFileSync: jest.fn(),
  readdirSync: jest.fn()
}));

describe('DependencyChecker', () => {
  let dependencyChecker: DependencyChecker;
  
  beforeEach(() => {
    dependencyChecker = new DependencyChecker();
    jest.clearAllMocks();
  });
  
  describe('check', () => {
    it('should return empty array when no dependency file is found', () => {
      // Mock that no dependency file exists
      (fs.existsSync as jest.Mock).mockReturnValue(false);
      
      const result = dependencyChecker.check('/path/to/file.js', 'javascript');
      
      expect(result).toEqual([]);
      expect(fs.existsSync).toHaveBeenCalled();
    });
    
    it('should detect vulnerable JavaScript dependencies', () => {
      // Mock that package.json exists
      (fs.existsSync as jest.Mock).mockReturnValue(true);
      
      // Mock file reading for package.json with vulnerable dependencies
      (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({
        dependencies: {
          'lodash': '4.17.19', // Vulnerable version
          'express': '4.17.3'  // Safe version
        }
      }));
      
      const result = dependencyChecker.check('/path/to/file.js', 'javascript');
      
      expect(result.length).toBeGreaterThan(0);
      expect(result[0].ruleId).toContain('lodash');
      expect(result[0].message).toContain('Vulnerable dependency');
      expect(result[0].severity).toBe('high');
    });
    
    it('should detect vulnerable Python dependencies', () => {
      // Mock that requirements.txt exists
      (fs.existsSync as jest.Mock).mockReturnValue(true);
      
      // Mock file reading for requirements.txt with vulnerable dependencies
      (fs.readFileSync as jest.Mock).mockReturnValue(
        'django==3.2.12\nflask==1.1.4\nrequests==2.26.0'
      );
      
      const result = dependencyChecker.check('/path/to/file.py', 'python');
      
      expect(result.length).toBeGreaterThan(0);
      // Check that django vulnerability was found (version < 3.2.13)
      const djangoVuln = result.find(v => v.ruleId.includes('django'));
      expect(djangoVuln).toBeDefined();
      expect(djangoVuln?.message).toContain('django');
    });
    
    it('should handle errors in dependency file parsing', () => {
      // Mock that package.json exists
      (fs.existsSync as jest.Mock).mockReturnValue(true);
      
      // Mock file reading with invalid JSON
      (fs.readFileSync as jest.Mock).mockReturnValue('{ invalid json }');
      
      // Should not throw an error
      const result = dependencyChecker.check('/path/to/file.js', 'javascript');
      
      expect(result).toEqual([]);
    });
  });
  
  describe('version checking', () => {
    // Use the private method via any cast to test it directly
    it('should correctly identify vulnerable version patterns', () => {
      const isVersionVulnerable = (dependencyChecker as any).isVersionVulnerable.bind(dependencyChecker);
      
      // Test version comparison with < pattern
      expect(isVersionVulnerable('4.17.19', '<4.17.20')).toBe(true);
      expect(isVersionVulnerable('4.17.20', '<4.17.20')).toBe(false);
      expect(isVersionVulnerable('4.17.21', '<4.17.20')).toBe(false);
      
      // Test with ^ version indicator
      expect(isVersionVulnerable('^4.17.19', '<4.17.20')).toBe(true);
      
      // Test with ~ version indicator
      expect(isVersionVulnerable('~4.17.19', '<4.17.20')).toBe(true);
    });
    
    it('should correctly compare version strings', () => {
      const compareVersions = (dependencyChecker as any).compareVersions.bind(dependencyChecker);
      
      expect(compareVersions('1.0.0', '1.0.0')).toBe(0);
      expect(compareVersions('1.0.0', '1.0.1')).toBe(-1);
      expect(compareVersions('1.0.1', '1.0.0')).toBe(1);
      expect(compareVersions('1.2.3', '1.3.0')).toBe(-1);
      expect(compareVersions('2.0.0', '1.9.9')).toBe(1);
      
      // Test with non-numeric parts
      expect(compareVersions('1.0.0-alpha', '1.0.0')).toBe(-1);
    });
  });
  
  describe('findFileUpwards', () => {
    it('should find package.json in parent directory', () => {
      const findFileUpwards = (dependencyChecker as any).findFileUpwards.bind(dependencyChecker);
      
      // Mock fs.existsSync to return true only for a specific path
      (fs.existsSync as jest.Mock).mockImplementation((filePath: string) => {
        return filePath === '/path/to/package.json';
      });
      
      const result = findFileUpwards('package.json', '/path/to/src');
      
      expect(result).toBe('/path/to/package.json');
    });
    
    it('should handle glob patterns', () => {
      const findFileUpwards = (dependencyChecker as any).findFileUpwards.bind(dependencyChecker);
      
      // Mock fs.readdirSync to return a list of files
      (fs.readdirSync as jest.Mock).mockReturnValue(['project.csproj', 'README.md']);
      
      // Mock fs.existsSync to return false (we're testing glob patterns)
      (fs.existsSync as jest.Mock).mockReturnValue(false);
      
      const result = findFileUpwards(['*.csproj'], '/path/to/src');
      
      expect(result).toBe('/path/to/src/project.csproj');
    });
    
    it('should return null if no matching file is found', () => {
      const findFileUpwards = (dependencyChecker as any).findFileUpwards.bind(dependencyChecker);
      
      // Mock fs.existsSync and fs.readdirSync to return false/empty
      (fs.existsSync as jest.Mock).mockReturnValue(false);
      (fs.readdirSync as jest.Mock).mockReturnValue([]);
      
      const result = findFileUpwards('package.json', '/path/to/src');
      
      expect(result).toBeNull();
    });
  });
  
  describe('parseDependencyFile', () => {
    it('should parse package.json correctly', () => {
      const parseDependencyFile = (dependencyChecker as any).parseDependencyFile.bind(dependencyChecker);
      
      (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({
        dependencies: {
          'lodash': '4.17.19',
          'express': '4.17.3'
        },
        devDependencies: {
          'jest': '27.0.0'
        }
      }));
      
      const result = parseDependencyFile('/path/to/package.json', 'javascript');
      
      expect(result).toEqual({
        'lodash': '4.17.19',
        'express': '4.17.3',
        'jest': '27.0.0'
      });
    });
    
    it('should parse requirements.txt correctly', () => {
      const parseDependencyFile = (dependencyChecker as any).parseDependencyFile.bind(dependencyChecker);
      
      (fs.readFileSync as jest.Mock).mockReturnValue(
        'django==3.2.12\nflask==1.1.4\nrequests>=2.26.0'
      );
      
      const result = parseDependencyFile('/path/to/requirements.txt', 'python');
      
      expect(result).toEqual({
        'django': '3.2.12',
        'flask': '1.1.4',
        'requests': '2.26.0'
      });
    });
    
    it('should parse pom.xml correctly', () => {
      const parseDependencyFile = (dependencyChecker as any).parseDependencyFile.bind(dependencyChecker);
      
      (fs.readFileSync as jest.Mock).mockReturnValue(`
        <project>
          <dependencies>
            <dependency>
              <groupId>org.apache.logging.log4j</groupId>
              <artifactId>log4j-core</artifactId>
              <version>2.14.0</version>
            </dependency>
          </dependencies>
        </project>
      `);
      
      const result = parseDependencyFile('/path/to/pom.xml', 'java');
      
      expect(result).toEqual({
        'log4j-core': '2.14.0'
      });
    });
    
    it('should parse .csproj file correctly', () => {
      const parseDependencyFile = (dependencyChecker as any).parseDependencyFile.bind(dependencyChecker);
      
      (fs.readFileSync as jest.Mock).mockReturnValue(`
        <Project>
          <ItemGroup>
            <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
          </ItemGroup>
        </Project>
      `);
      
      const result = parseDependencyFile('/path/to/project.csproj', 'csharp');
      
      expect(result).toEqual({
        'Newtonsoft.Json': '12.0.3'
      });
    });
  });
}); 