"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMasterHash = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const constants_1 = require("./constants");
const getMasterHash = async (master_key, password) => {
    const salt = Buffer.from(password);
    const key = await crypto_1.default.subtle.importKey("raw", // only raw format
    Buffer.from(master_key), // BufferSource
    "PBKDF2", false, // only false
    ["deriveBits", "deriveKey"]);
    const derivedBits = await crypto_1.default.subtle.deriveBits({
        name: "PBKDF2",
        salt,
        iterations: constants_1.ITERATIONS,
        hash: "SHA-256",
    }, key, constants_1.HASH_LENGTH);
    return Buffer.from(derivedBits).toString("base64");
};
exports.getMasterHash = getMasterHash;
//# sourceMappingURL=master_hash.js.map