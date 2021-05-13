"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getEncryptionKey = exports.getMasterKey = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const constants_1 = require("./constants");
const importKey = (key, algorithm) => crypto_1.default.subtle.importKey("raw", // only raw format
Buffer.from(key, "base64"), // BufferSource
algorithm, false, // only false
["deriveBits", "deriveKey"]);
const getMasterKey = async (email, password) => {
    const salt = Buffer.from(email);
    const key = await importKey(password, "PBKDF2");
    const derivedBits = await crypto_1.default.subtle.deriveBits({
        name: "PBKDF2",
        salt,
        iterations: constants_1.ITERATIONS,
        hash: "SHA-256",
    }, key, constants_1.HASH_LENGTH);
    return Buffer.from(derivedBits).toString("base64");
};
exports.getMasterKey = getMasterKey;
const HKDF_ALGORITHM = {
    name: "HMAC",
    hash: "SHA-256",
    length: constants_1.HASH_LENGTH,
};
const hkdfParameters = (info) => ({
    name: "HKDF",
    salt: Buffer.from("sign"),
    info: Buffer.from(info),
    hash: "SHA-256",
});
const hkdfDeriveAndExport = async (key, info) => {
    const key_crypto = await crypto_1.default.subtle.deriveKey(hkdfParameters(info), key, HKDF_ALGORITHM, true, ["sign", "verify"]);
    const exported_key = await crypto_1.default.subtle.exportKey("raw", key_crypto);
    return exported_key;
};
const getEncryptionKey = async (master_key) => {
    const key = await importKey(master_key, "HKDF");
    const encryption_key = await hkdfDeriveAndExport(key, "enc");
    const encryption_mac = await hkdfDeriveAndExport(key, "mac");
    return Buffer.concat([
        Buffer.from(encryption_key),
        Buffer.from(encryption_mac),
    ]).toString("base64");
};
exports.getEncryptionKey = getEncryptionKey;
//# sourceMappingURL=get_key.js.map