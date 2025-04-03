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
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadRules = loadRules;
exports.loadCustomRules = loadCustomRules;
const javascript_1 = require("./javascript");
const python_1 = require("./python");
const java_1 = require("./java");
const csharp_1 = require("./csharp");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/**
 * Loads all built-in security rules
 */
function loadRules() {
    return [
        ...javascript_1.javascriptRules,
        ...python_1.pythonRules,
        ...java_1.javaRules,
        ...csharp_1.csharpRules
    ];
}
/**
 * Loads custom rules from the specified directory path
 */
function loadCustomRules(directoryPath) {
    if (!fs.existsSync(directoryPath)) {
        return [];
    }
    const customRules = [];
    const files = fs.readdirSync(directoryPath);
    for (const file of files) {
        if (file.endsWith('.js') || file.endsWith('.ts')) {
            try {
                const rulePath = path.join(directoryPath, file);
                // eslint-disable-next-line @typescript-eslint/no-var-requires
                const ruleModule = require(rulePath);
                if (ruleModule.default && isValidRule(ruleModule.default)) {
                    customRules.push(ruleModule.default);
                }
                else if (isValidRule(ruleModule)) {
                    customRules.push(ruleModule);
                }
            }
            catch (error) {
                console.error(`Error loading custom rule from ${file}:`, error);
            }
        }
    }
    return customRules;
}
/**
 * Validates that a rule has the required properties and methods
 */
function isValidRule(rule) {
    return (rule &&
        typeof rule.id === 'string' &&
        typeof rule.name === 'string' &&
        typeof rule.description === 'string' &&
        (rule.severity === 'info' ||
            rule.severity === 'warning' ||
            rule.severity === 'error' ||
            rule.severity === 'critical') &&
        typeof rule.category === 'string' &&
        typeof rule.check === 'function');
}
//# sourceMappingURL=ruleLoader.js.map