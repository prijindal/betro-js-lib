"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getEncryptionKey = exports.getMasterKey = void 0;
const crypto_1 = __importDefault(require("crypto"));
const futoin_hkdf_1 = __importDefault(require("futoin-hkdf"));
const HASH_LENGTH = 64;
const KEY_LENGTH = 32;
const getMasterKey = (email, password) => {
    const salt = Buffer.from(email, "base64");
    const hash = crypto_1.default.scryptSync(password, salt, KEY_LENGTH);
    return hash.toString("base64");
};
exports.getMasterKey = getMasterKey;
const getEncryptionKey = (master_key) => {
    const hkdf_prk = futoin_hkdf_1.default.extract("sha256", HASH_LENGTH, master_key, "sign");
    const encryption_key = futoin_hkdf_1.default
        .expand("sha256", HASH_LENGTH, hkdf_prk, KEY_LENGTH, "enc")
        .toString("base64");
    const encryption_mac = futoin_hkdf_1.default
        .expand("sha256", HASH_LENGTH, hkdf_prk, KEY_LENGTH, "mac")
        .toString("base64");
    return {
        encryption_key,
        encryption_mac,
    };
};
exports.getEncryptionKey = getEncryptionKey;
//# sourceMappingURL=get_key.js.map