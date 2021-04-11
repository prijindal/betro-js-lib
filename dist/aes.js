"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.aesDecrypt = exports.aesEncrypt = void 0;
const crypto_1 = __importDefault(require("crypto"));
const aesEncrypt = (encryption_key, encryption_mac, data) => {
    const hash = crypto_1.default.createHash("sha256");
    hash.update(encryption_key);
    const keyBytes = hash.digest();
    const iv = crypto_1.default.randomBytes(16);
    const cipher = crypto_1.default.createCipheriv("aes-256-cfb", keyBytes, iv);
    const enc = [cipher.update(data)];
    enc.push(cipher.final());
    const encrypted_data = Buffer.concat(enc);
    const hmac = crypto_1.default.createHmac("sha256", encryption_mac);
    hmac.update(Buffer.concat([iv, encrypted_data]));
    const encrypted = Buffer.concat([hmac.digest(), iv, encrypted_data]);
    return encrypted.toString("base64");
};
exports.aesEncrypt = aesEncrypt;
const aesDecrypt = (encryption_key, encryption_mac, data) => {
    const hmac = crypto_1.default.createHmac("sha256", encryption_mac);
    const data_bytes = Buffer.from(data, "base64");
    const verify = data_bytes.slice(0, 32);
    hmac.update(data_bytes.slice(32));
    if (Buffer.compare(hmac.digest(), verify) !== 0) {
        return {
            isVerified: false,
        };
    }
    const iv = data_bytes.slice(32, 48);
    const hash = crypto_1.default.createHash("sha256");
    hash.update(encryption_key);
    const keyBytes = hash.digest();
    const decipher = crypto_1.default.createDecipheriv("aes-256-cfb", keyBytes, iv);
    let res = decipher.update(data_bytes.slice(48));
    res = Buffer.concat([res, decipher.final()]);
    return { isVerified: true, data: res };
};
exports.aesDecrypt = aesDecrypt;
//# sourceMappingURL=aes.js.map
