"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMasterHash = void 0;
const webcrypto_1 = require("@peculiar/webcrypto");
const crypto = new webcrypto_1.Crypto();
const constants_1 = require("./constants");
const getMasterHash = async (master_key, password) => {
    const salt = Buffer.from(password, "base64");
    const key = await crypto.subtle.importKey("raw", // only raw format
    Buffer.from(master_key), // BufferSource
    "PBKDF2", false, // only false
    ["deriveBits", "deriveKey"]);
    const derivedBits = await crypto.subtle.deriveBits({
        name: "PBKDF2",
        salt,
        iterations: constants_1.ITERATIONS,
        hash: "SHA-256",
    }, key, constants_1.HASH_LENGTH);
    return Buffer.from(derivedBits).toString("base64");
};
exports.getMasterHash = getMasterHash;
//# sourceMappingURL=master_hash.js.map
