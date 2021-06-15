"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.rsaDecrypt = exports.rsaEncrypt = exports.generateRsaPair = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const constants_1 = require("./constants");
const RSA_ALGORITHM = "RSA-OAEP";
const KEY_SIZE = 2048;
const generateRsaPair = async () => {
    const keys = await crypto_1.default.subtle.generateKey({
        name: RSA_ALGORITHM,
        hash: constants_1.HASH_ALGORITHM,
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: KEY_SIZE, // 1024, 2048, or 4096
    }, true, ["encrypt", "decrypt"]);
    const publicKey = await crypto_1.default.subtle.exportKey("spki", keys.publicKey);
    const privateKey = await crypto_1.default.subtle.exportKey("pkcs8", keys.privateKey);
    return {
        publicKey: Buffer.from(publicKey).toString("base64"),
        privateKey: Buffer.from(privateKey).toString("base64"),
    };
};
exports.generateRsaPair = generateRsaPair;
const importRsaKey = (format, key, keyUsage) => crypto_1.default.subtle.importKey(format, Uint8Array.from(Buffer.from(key, "base64")), {
    name: RSA_ALGORITHM,
    hash: constants_1.HASH_ALGORITHM,
}, false, keyUsage);
const rsaEncrypt = async (public_key, data) => {
    const publicKey = await importRsaKey("spki", public_key, ["encrypt"]);
    const encData = await crypto_1.default.subtle.encrypt({
        name: RSA_ALGORITHM,
    }, publicKey, // RSA public key
    data // BufferSource
    );
    return Buffer.from(encData).toString("base64");
};
exports.rsaEncrypt = rsaEncrypt;
const rsaDecrypt = async (private_key, encrypted) => {
    const privateKey = await importRsaKey("pkcs8", private_key, ["decrypt"]);
    try {
        const data = await crypto_1.default.subtle.decrypt({
            name: RSA_ALGORITHM,
        }, privateKey, Buffer.from(encrypted, "base64"));
        return Buffer.from(data);
    }
    catch (e) {
        return null;
    }
};
exports.rsaDecrypt = rsaDecrypt;
//# sourceMappingURL=rsa.js.map