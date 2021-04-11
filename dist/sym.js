"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.symDecrypt = exports.symEncrypt = exports.generateSymKey = void 0;
const webcrypto_1 = require("@peculiar/webcrypto");
const crypto = new webcrypto_1.Crypto();
const algorithm = "AES-CBC";
const KEY_SIZE = 256;
const IV_LENGTH = 16;
const generateSymKey = async () => {
    const key = await crypto.subtle.generateKey({
        name: algorithm,
        length: KEY_SIZE,
    }, true, ["encrypt"]);
    const raw = await crypto.subtle.exportKey("raw", key);
    return Buffer.from(raw).toString("base64");
};
exports.generateSymKey = generateSymKey;
const symEncrypt = async (sym_key, data) => {
    const key = await crypto.subtle.importKey("raw", Buffer.from(sym_key, "base64"), algorithm, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encData = await crypto.subtle.encrypt({
        name: algorithm,
        iv,
    }, key, data);
    const encrypted_data = Buffer.from(encData);
    const encrypted = Buffer.concat([iv, encrypted_data]);
    return encrypted.toString("base64");
};
exports.symEncrypt = symEncrypt;
const symDecrypt = async (sym_key, encrypted_data) => {
    const key = await crypto.subtle.importKey("raw", // raw or jwk
    Buffer.from(sym_key, "base64"), algorithm, false, // extractable
    ["decrypt"]);
    const data_bytes = Buffer.from(encrypted_data, "base64");
    const iv = data_bytes.slice(0, IV_LENGTH);
    const data = await crypto.subtle.decrypt({
        name: algorithm,
        iv, // BufferSource
    }, key, // AES key
    data_bytes.slice(IV_LENGTH) // BufferSource
    );
    return Buffer.from(data);
};
exports.symDecrypt = symDecrypt;
//# sourceMappingURL=sym.js.map