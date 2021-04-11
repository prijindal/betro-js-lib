"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.aesDecrypt = exports.aesEncrypt = void 0;
const webcrypto_1 = require("@peculiar/webcrypto");
const crypto = new webcrypto_1.Crypto();
const aesEncrypt = async (encryption_key, encryption_mac, data) => {
    const key = await crypto.subtle.importKey("raw", Buffer.from(encryption_key, "base64"), "AES-CBC", false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const enc = await crypto.subtle.encrypt({
        name: "AES-CBC",
        iv,
    }, key, data);
    const encrypted_data = Buffer.from(enc);
    const encryption_mac_urlencoded = encryption_mac
        .replace("+", "-")
        .replace("/", "_")
        .replace(/=+$/, "");
    const hmac = await crypto.subtle.importKey("jwk", {
        alg: "HS256",
        ext: true,
        k: encryption_mac_urlencoded,
        key_ops: ["sign", "verify"],
        kty: "oct",
    }, {
        name: "HMAC",
        hash: "SHA-256",
    }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", hmac, Buffer.concat([iv, encrypted_data]));
    const encrypted = Buffer.concat([Buffer.from(signature), iv, encrypted_data]);
    return encrypted.toString("base64");
};
exports.aesEncrypt = aesEncrypt;
const aesDecrypt = async (encryption_key, encryption_mac, encrypted_data) => {
    const data_bytes = Buffer.from(encrypted_data, "base64");
    const encryption_mac_urlencoded = encryption_mac
        .replace("+", "-")
        .replace("/", "_")
        .replace(/=+$/, "");
    const hmac = await crypto.subtle.importKey("jwk", {
        alg: "HS256",
        ext: true,
        k: encryption_mac_urlencoded,
        key_ops: ["sign", "verify"],
        kty: "oct",
    }, {
        name: "HMAC",
        hash: "SHA-256",
    }, false, ["verify"]);
    const isVerified = await crypto.subtle.verify("HMAC", hmac, data_bytes.slice(0, 32), data_bytes.slice(32));
    if (isVerified === false) {
        return {
            isVerified: isVerified,
            data: null,
        };
    }
    const key = await crypto.subtle.importKey("raw", // raw or jwk
    Buffer.from(encryption_key, "base64"), "AES-CBC", false, // extractable
    ["decrypt"]);
    const iv = data_bytes.slice(32, 48);
    const data = await crypto.subtle.decrypt({
        name: "AES-CBC",
        iv,
    }, key, data_bytes.slice(48));
    return { isVerified: true, data: Buffer.from(data) };
};
exports.aesDecrypt = aesDecrypt;
//# sourceMappingURL=aes.js.map