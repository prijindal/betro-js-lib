"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getEncryptionKey = exports.getMasterKey = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const constants_1 = require("./constants");
const getMasterKey = async (email, password) => {
    const salt = Buffer.from(email);
    const key = await crypto_1.default.subtle.importKey("raw", // only raw format
    Buffer.from(password), // BufferSource
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
exports.getMasterKey = getMasterKey;
const getEncryptionKey = async (master_key) => {
    const key = await crypto_1.default.subtle.importKey("raw", // only raw format
    Buffer.from(master_key, "base64"), // BufferSource
    "HKDF", false, // only false
    ["deriveBits", "deriveKey"]);
    const encryption_key_crypto = await crypto_1.default.subtle.deriveKey({
        name: "HKDF",
        salt: Buffer.from("sign"),
        info: Buffer.from("enc"),
        hash: "SHA-256",
    }, key, {
        name: "HMAC",
        hash: "SHA-256",
        length: constants_1.HASH_LENGTH,
    }, true, ["sign", "verify"]);
    const encryption_mac_crypto = await crypto_1.default.subtle.deriveKey({
        name: "HKDF",
        salt: Buffer.from("sign"),
        info: Buffer.from("mac"),
        hash: "SHA-256",
    }, key, {
        name: "HMAC",
        hash: "SHA-256",
        length: constants_1.HASH_LENGTH,
    }, true, ["sign", "verify"]);
    const encryption_key = await crypto_1.default.subtle.exportKey("raw", encryption_key_crypto);
    const encryption_mac = await crypto_1.default.subtle.exportKey("raw", encryption_mac_crypto);
    return {
        encryption_key: Buffer.from(encryption_key).toString("base64"),
        encryption_mac: Buffer.from(encryption_mac).toString("base64"),
    };
};
exports.getEncryptionKey = getEncryptionKey;
//# sourceMappingURL=get_key.js.map