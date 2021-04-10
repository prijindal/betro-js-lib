"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.rsaDecrypt = exports.rsaEncrypt = exports.generateRsaPair = void 0;
const crypto_1 = __importDefault(require("crypto"));
const generateRsaPair = () => {
    const { publicKey, privateKey } = crypto_1.default.generateKeyPairSync("rsa", {
        modulusLength: 4096,
        publicKeyEncoding: {
            type: "spki",
            format: "pem",
        },
        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
        },
    });
    return { publicKey, privateKey };
};
exports.generateRsaPair = generateRsaPair;
const rsaEncrypt = (publicKey, data) => {
    const encrypted = crypto_1.default.publicEncrypt(publicKey, data);
    return encrypted.toString("base64");
};
exports.rsaEncrypt = rsaEncrypt;
const rsaDecrypt = (privateKey, encrypted) => {
    const buffer = Buffer.from(encrypted, "base64");
    const data = crypto_1.default.privateDecrypt(privateKey, buffer);
    return data;
};
exports.rsaDecrypt = rsaDecrypt;
//# sourceMappingURL=rsa.js.map