"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.symDecrypt = exports.symDecryptBuffer = exports.symEncrypt = exports.generateSymKey = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const constants_1 = require("./constants");
const HMAC_ALGORITHM = {
    name: "HMAC",
    hash: constants_1.HASH_ALGORITHM,
};
const HMAC_LENGTH = constants_1.HASH_LENGTH / 8;
const algorithm = "AES-CBC";
const KEY_SIZE = 256;
const IV_LENGTH = 16;
const generateSymKey = async () => {
    const [key, hmac] = await Promise.all([
        crypto_1.default.subtle.generateKey({
            name: algorithm,
            length: KEY_SIZE,
        }, true, ["encrypt", "decrypt"]),
        window.crypto.subtle.generateKey(HMAC_ALGORITHM, true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"] //can be any combination of "sign" and "verify"
        ),
    ]);
    const [raw, rawHmac] = await Promise.all([
        crypto_1.default.subtle.exportKey("raw", key),
        crypto_1.default.subtle.exportKey("raw", hmac),
    ]);
    return Buffer.concat([Buffer.from(raw), Buffer.from(rawHmac)]).toString("base64");
};
exports.generateSymKey = generateSymKey;
const importKey = (key, keyUsage) => crypto_1.default.subtle.importKey("raw", key, algorithm, false, keyUsage);
const importHmac = (hmac, keyUsage) => crypto_1.default.subtle.importKey("raw", hmac, HMAC_ALGORITHM, false, keyUsage);
const symEncrypt = async (sym_key, data) => {
    const buffer = Buffer.from(sym_key, "base64");
    const keyBuffer = buffer.slice(0, KEY_SIZE / 8);
    const hmacBuffer = buffer.slice(KEY_SIZE / 8);
    const [key, hmac] = await Promise.all([
        importKey(keyBuffer, ["encrypt"]),
        importHmac(hmacBuffer, ["sign"]),
    ]);
    const iv = Buffer.from(crypto_1.default.getRandomValues(new Uint8Array(IV_LENGTH)));
    const encData = await crypto_1.default.subtle.encrypt({
        name: algorithm,
        iv,
    }, key, data);
    const encrypted_data = Buffer.from(encData);
    const signature = await crypto_1.default.subtle.sign("HMAC", hmac, Buffer.concat([iv, encrypted_data]));
    const encrypted = Buffer.concat([Buffer.from(signature), iv, encrypted_data]);
    return encrypted.toString("base64");
};
exports.symEncrypt = symEncrypt;
const symDecryptBuffer = async (buffer, encrypted_data) => {
    const keyBuffer = buffer.slice(0, KEY_SIZE / 8);
    const hmacBuffer = buffer.slice(KEY_SIZE / 8);
    const [key, hmac] = await Promise.all([
        importKey(keyBuffer, ["decrypt"]),
        importHmac(hmacBuffer, ["verify"]),
    ]);
    const data_bytes = Buffer.from(encrypted_data, "base64");
    const iv = data_bytes.slice(HMAC_LENGTH, HMAC_LENGTH + IV_LENGTH);
    const isVerified = await crypto_1.default.subtle.verify("HMAC", hmac, data_bytes.slice(0, HMAC_LENGTH), data_bytes.slice(HMAC_LENGTH));
    if (isVerified == false) {
        return null;
    }
    const data = await crypto_1.default.subtle.decrypt({
        name: algorithm,
        iv, // BufferSource
    }, key, // AES key
    data_bytes.slice(32 + IV_LENGTH) // BufferSource
    );
    return Buffer.from(data);
};
exports.symDecryptBuffer = symDecryptBuffer;
const symDecrypt = async (sym_key, encrypted_data) => {
    const buffer = Buffer.from(sym_key, "base64");
    return exports.symDecryptBuffer(buffer, encrypted_data);
};
exports.symDecrypt = symDecrypt;
//# sourceMappingURL=sym.js.map