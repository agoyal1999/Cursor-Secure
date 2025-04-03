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
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadCustomRules = exports.loadRules = exports.CSharpParser = exports.JavaParser = exports.PythonParser = exports.JavaScriptParser = exports.Scanner = exports.csharpRules = exports.javaRules = exports.pythonRules = exports.javascriptRules = void 0;
// Export rule sets
var javascript_1 = require("./rules/javascript");
Object.defineProperty(exports, "javascriptRules", { enumerable: true, get: function () { return javascript_1.javascriptRules; } });
var python_1 = require("./rules/python");
Object.defineProperty(exports, "pythonRules", { enumerable: true, get: function () { return python_1.pythonRules; } });
var java_1 = require("./rules/java");
Object.defineProperty(exports, "javaRules", { enumerable: true, get: function () { return java_1.javaRules; } });
var csharp_1 = require("./rules/csharp");
Object.defineProperty(exports, "csharpRules", { enumerable: true, get: function () { return csharp_1.csharpRules; } });
// Export interfaces
__exportStar(require("./interfaces"), exports);
// Export scanner
var scanner_1 = require("./scanner");
Object.defineProperty(exports, "Scanner", { enumerable: true, get: function () { return scanner_1.Scanner; } });
// Export parsers
var javascript_2 = require("./parsers/javascript");
Object.defineProperty(exports, "JavaScriptParser", { enumerable: true, get: function () { return javascript_2.JavaScriptParser; } });
var python_2 = require("./parsers/python");
Object.defineProperty(exports, "PythonParser", { enumerable: true, get: function () { return python_2.PythonParser; } });
var java_2 = require("./parsers/java");
Object.defineProperty(exports, "JavaParser", { enumerable: true, get: function () { return java_2.JavaParser; } });
var csharp_2 = require("./parsers/csharp");
Object.defineProperty(exports, "CSharpParser", { enumerable: true, get: function () { return csharp_2.CSharpParser; } });
// Export utilities
var ruleLoader_1 = require("./rules/ruleLoader");
Object.defineProperty(exports, "loadRules", { enumerable: true, get: function () { return ruleLoader_1.loadRules; } });
Object.defineProperty(exports, "loadCustomRules", { enumerable: true, get: function () { return ruleLoader_1.loadCustomRules; } });
//# sourceMappingURL=index.js.map