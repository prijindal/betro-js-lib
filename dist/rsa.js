"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.rsaDecrypt = exports.rsaEncrypt = exports.generateRsaPair = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const generateRsaPair = async () => {
    const keys = await crypto_1.default.subtle.generateKey({
        name: "RSA-OAEP",
        hash: "SHA-512",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 4096, // 1024, 2048, or 4096
    }, true, ["encrypt", "decrypt"]);
    const publicKey = await crypto_1.default.subtle.exportKey("spki", keys.publicKey);
    const privateKey = await crypto_1.default.subtle.exportKey("pkcs8", keys.privateKey);
    return {
        publicKey: Buffer.from(publicKey).toString("base64"),
        privateKey: Buffer.from(privateKey).toString("base64"),
    };
};
exports.generateRsaPair = generateRsaPair;
const rsaEncrypt = async (public_key, data) => {
    const publicKey = await crypto_1.default.subtle.importKey("spki", Buffer.from(public_key, "base64"), {
        name: "RSA-OAEP",
        hash: "SHA-256",
    }, false, ["encrypt"]);
    const encData = await crypto_1.default.subtle.encrypt({
        name: "RSA-OAEP",
    }, publicKey, // RSA public key
    data // BufferSource
    );
    return Buffer.from(encData).toString("base64");
};
exports.rsaEncrypt = rsaEncrypt;
const rsaDecrypt = async (private_key, encrypted) => {
    const privateKey = await crypto_1.default.subtle.importKey("pkcs8", Buffer.from(private_key, "base64"), {
        name: "RSA-OAEP",
        hash: "SHA-256",
    }, false, ["decrypt"]);
    const data = await crypto_1.default.subtle.decrypt({
        name: "RSA-OAEP",
    }, privateKey, Buffer.from(encrypted, "base64"));
    return Buffer.from(data);
};
exports.rsaDecrypt = rsaDecrypt;
//# sourceMappingURL=rsa.js.map