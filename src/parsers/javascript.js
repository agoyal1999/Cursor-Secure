"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JavaScriptParser = void 0;
const acorn = __importStar(require("acorn"));
const acorn_jsx_1 = __importDefault(require("acorn-jsx"));
class JavaScriptParser {
    constructor() {
        // Create parser with JSX support
        this.parser = acorn.Parser.extend((0, acorn_jsx_1.default)());
    }
    /**
     * Parse JavaScript code into an AST
     */
    parse(code) {
        try {
            return this.parser.parse(code, {
                ecmaVersion: 2022,
                sourceType: 'module',
                locations: true,
                allowAwaitOutsideFunction: true,
                allowImportExportEverywhere: true
            });
        }
        catch (error) {
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
    getLanguage() {
        return 'javascript';
    }
}
exports.JavaScriptParser = JavaScriptParser;
//# sourceMappingURL=javascript.js.map