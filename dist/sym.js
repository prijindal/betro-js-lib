"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.symDecrypt = exports.symEncrypt = exports.generateSymKey = void 0;
const crypto_1 = __importDefault(require("crypto"));
const algorithm = "aes-256-cbc";
const KEY_SIZE = 32;
const IV_LENGTH = 16;
const generateSymKey = () => {
    const symKey = crypto_1.default.randomBytes(KEY_SIZE);
    return symKey.toString("base64");
};
exports.generateSymKey = generateSymKey;
const symEncrypt = (sym_key, data) => {
    const hash = crypto_1.default.createHash("sha256");
    hash.update(sym_key);
    const keyBytes = hash.digest();
    const iv = crypto_1.default.randomBytes(IV_LENGTH);
    const cipher = crypto_1.default.createCipheriv(algorithm, keyBytes, iv);
    const enc = [cipher.update(data)];
    enc.push(cipher.final());
    const encrypted_data = Buffer.concat(enc);
    const encrypted = Buffer.concat([iv, encrypted_data]);
    return encrypted.toString("base64");
};
exports.symEncrypt = symEncrypt;
const symDecrypt = (sym_key, encrypted_data) => {
    const data_bytes = Buffer.from(encrypted_data, "base64");
    const iv = data_bytes.slice(0, IV_LENGTH);
    const hash = crypto_1.default.createHash("sha256");
    hash.update(sym_key);
    const keyBytes = hash.digest();
    const decipher = crypto_1.default.createDecipheriv(algorithm, keyBytes, iv);
    let res = decipher.update(data_bytes.slice(IV_LENGTH));
    res = Buffer.concat([res, decipher.final()]);
    return res;
};
exports.symDecrypt = symDecrypt;
//# sourceMappingURL=sym.js.map