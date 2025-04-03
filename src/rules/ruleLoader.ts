import { Rule } from '../interfaces';
import { javascriptRules } from './javascript';
import { pythonRules } from './python';
import { javaRules } from './java';
import { csharpRules } from './csharp';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Loads all built-in security rules
 */
export function loadRules(): Rule[] {
  return [
    ...javascriptRules,
    ...pythonRules,
    ...javaRules,
    ...csharpRules
  ];
}

/**
 * Loads custom rules from the specified directory path
 */
export function loadCustomRules(directoryPath: string): Rule[] {
  if (!fs.existsSync(directoryPath)) {
    return [];
  }

  const customRules: Rule[] = [];
  const files = fs.readdirSync(directoryPath);

  for (const file of files) {
    if (file.endsWith('.js') || file.endsWith('.ts')) {
      try {
        const rulePath = path.join(directoryPath, file);
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const ruleModule = require(rulePath);
        
        if (ruleModule.default && isValidRule(ruleModule.default)) {
          customRules.push(ruleModule.default);
        } else if (isValidRule(ruleModule)) {
          customRules.push(ruleModule);
        }
      } catch (error) {
        console.error(`Error loading custom rule from ${file}:`, error);
      }
    }
  }

  return customRules;
}

/**
 * Validates that a rule has the required properties and methods
 */
function isValidRule(rule: any): rule is Rule {
  return (
    rule &&
    typeof rule.id === 'string' &&
    typeof rule.name === 'string' &&
    typeof rule.description === 'string' &&
    (rule.severity === 'info' || 
     rule.severity === 'warning' || 
     rule.severity === 'error' || 
     rule.severity === 'critical') &&
    typeof rule.category === 'string' &&
    typeof rule.check === 'function'
  );
} 