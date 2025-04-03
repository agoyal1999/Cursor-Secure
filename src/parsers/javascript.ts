import { Parser } from './index';
import { SupportedLanguage } from '../interfaces';
import * as acorn from 'acorn';
import acornJsx from 'acorn-jsx';

export class JavaScriptParser implements Parser {
  private parser: any;

  constructor() {
    // Create parser with JSX support
    this.parser = acorn.Parser.extend(acornJsx());
  }

  /**
   * Parse JavaScript code into an AST
   */
  parse(code: string): any {
    try {
      return this.parser.parse(code, {
        ecmaVersion: 2022,
        sourceType: 'module',
        locations: true,
        allowAwaitOutsideFunction: true,
        allowImportExportEverywhere: true
      });
    } catch (error) {
      console.error('Error parsing JavaScript code:', error);
      // Return a minimal AST on error to avoid crashes
      return {
        type: 'Program',
        body: [],
        sourceType: 'module'
      };
    }
  }

  /**
   * Returns the language supported by this parser
   */
  getLanguage(): SupportedLanguage {
    return 'javascript';
  }
} 