"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getEncryptionKey = exports.getMasterKey = void 0;
const webcrypto_1 = require("@peculiar/webcrypto");
const crypto = new webcrypto_1.Crypto();
const constants_1 = require("./constants");
const getMasterKey = async (email, password) => {
    const salt = Buffer.from(email, "base64");
    const key = await crypto.subtle.importKey("raw", // only raw format
    Buffer.from(password), // BufferSource
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
exports.getMasterKey = getMasterKey;
const getEncryptionKey = async (master_key) => {
    const key = await crypto.subtle.importKey("raw", // only raw format
    Buffer.from(master_key), // BufferSource
    "HKDF", false, // only false
    ["deriveBits", "deriveKey"]);
    const encryption_key = await crypto.subtle.deriveBits({
        name: "HKDF",
        salt: Buffer.from("sign"),
        info: Buffer.from("enc"),
        hash: "SHA-256",
    }, key, constants_1.HASH_LENGTH);
    const encryption_mac = await crypto.subtle.deriveBits({
        name: "HKDF",
        salt: Buffer.from("sign"),
        info: Buffer.from("mac"),
        hash: "SHA-256",
    }, key, constants_1.HASH_LENGTH);
    return {
        encryption_key: Buffer.from(encryption_key).toString("base64"),
        encryption_mac: Buffer.from(encryption_mac).toString("base64"),
    };
};
exports.getEncryptionKey = getEncryptionKey;
//# sourceMappingURL=get_key.js.map