import { SupportedLanguage } from '../interfaces';
import { JavaScriptParser } from './javascript';
import { PythonParser } from './python';
import { JavaParser } from './java';
import { CSharpParser } from './csharp';

export interface Parser {
  parse: (code: string) => any;
  getLanguage: () => SupportedLanguage;
}

/**
 * Returns the appropriate parser for the given language
 */
export function getParser(language: SupportedLanguage): Parser {
  switch (language) {
    case 'javascript':
      return new JavaScriptParser();
    case 'python':
      return new PythonParser();
    case 'java':
      return new JavaParser();
    case 'csharp':
      return new CSharpParser();
    default:
      throw new Error(`Unsupported language: ${language}`);
  }
} 