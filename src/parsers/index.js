"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getParser = getParser;
const javascript_1 = require("./javascript");
const python_1 = require("./python");
const java_1 = require("./java");
const csharp_1 = require("./csharp");
/**
 * Returns the appropriate parser for the given language
 */
function getParser(language) {
    switch (language) {
        case 'javascript':
            return new javascript_1.JavaScriptParser();
        case 'python':
            return new python_1.PythonParser();
        case 'java':
            return new java_1.JavaParser();
        case 'csharp':
            return new csharp_1.CSharpParser();
        default:
            throw new Error(`Unsupported language: ${language}`);
    }
}
//# sourceMappingURL=index.js.map