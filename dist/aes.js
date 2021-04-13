"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.aesDecrypt = exports.aesEncrypt = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const aesEncrypt = async (encryption_key, encryption_mac, data) => {
    const key = await crypto_1.default.subtle.importKey("raw", Buffer.from(encryption_key, "base64"), "AES-CBC", false, ["encrypt"]);
    const iv = Buffer.from(crypto_1.default.getRandomValues(new Uint8Array(16)));
    const enc = await crypto_1.default.subtle.encrypt({
        name: "AES-CBC",
        iv,
    }, key, data);
    const encrypted_data = Buffer.from(enc);
    const hmac = await crypto_1.default.subtle.importKey("raw", Buffer.from(encryption_mac, "base64"), {
        name: "HMAC",
        hash: "SHA-256",
    }, false, ["sign"]);
    const signature = await crypto_1.default.subtle.sign("HMAC", hmac, Buffer.concat([iv, encrypted_data]));
    const encrypted = Buffer.concat([Buffer.from(signature), iv, encrypted_data]);
    return encrypted.toString("base64");
};
exports.aesEncrypt = aesEncrypt;
const aesDecrypt = async (encryption_key, encryption_mac, encrypted_data) => {
    const data_bytes = Buffer.from(encrypted_data, "base64");
    const hmac = await crypto_1.default.subtle.importKey("raw", Buffer.from(encryption_mac, "base64"), {
        name: "HMAC",
        hash: "SHA-256",
    }, false, ["verify"]);
    const isVerified = await crypto_1.default.subtle.verify("HMAC", hmac, data_bytes.slice(0, 32), data_bytes.slice(32));
    if (isVerified === false) {
        return {
            isVerified: isVerified,
            data: null,
        };
    }
    const key = await crypto_1.default.subtle.importKey("raw", // raw or jwk
    Buffer.from(encryption_key, "base64"), "AES-CBC", false, // extractable
    ["decrypt"]);
    const iv = data_bytes.slice(32, 48);
    const data = await crypto_1.default.subtle.decrypt({
        name: "AES-CBC",
        iv,
    }, key, data_bytes.slice(48));
    return { isVerified: true, data: Buffer.from(data) };
};
exports.aesDecrypt = aesDecrypt;
//# sourceMappingURL=aes.js.map