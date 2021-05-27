"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveExchangeSymKey = exports.generateExchangePair = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const get_key_1 = require("./get_key");
const ECDH_ALGORITHM = "ECDH";
const NAMED_CURVE = "P-256";
const generateExchangePair = async () => {
    const keys = await crypto_1.default.subtle.generateKey({
        name: ECDH_ALGORITHM,
        namedCurve: NAMED_CURVE,
    }, true, ["deriveBits"]);
    const publicKey = await crypto_1.default.subtle.exportKey("spki", keys.publicKey);
    const privateKey = await crypto_1.default.subtle.exportKey("pkcs8", keys.privateKey);
    return {
        publicKey: Buffer.from(publicKey).toString("base64"),
        privateKey: Buffer.from(privateKey).toString("base64"),
    };
};
exports.generateExchangePair = generateExchangePair;
const importEcdhKey = (format, key, keyUsages) => crypto_1.default.subtle.importKey(format, Uint8Array.from(Buffer.from(key, "base64")), {
    name: ECDH_ALGORITHM,
    namedCurve: NAMED_CURVE,
}, false, keyUsages);
const deriveExchangeSymKey = async (public_key, private_key) => {
    const publicKey = await importEcdhKey("spki", public_key, []);
    const privateKey = await importEcdhKey("pkcs8", private_key, ["deriveBits"]);
    const keyData = await window.crypto.subtle.deriveBits({
        name: ECDH_ALGORITHM,
        // namedCurve: NAMED_CURVE, //can be "P-256", "P-384", or "P-521"
        public: publicKey, //an ECDH public key from generateKey or importKey
    }, privateKey, //your ECDH private key from generateKey or importKey
    256);
    return get_key_1.getEncryptionKey(Buffer.from(keyData).toString("base64"));
};
exports.deriveExchangeSymKey = deriveExchangeSymKey;
//# sourceMappingURL=ecdh.js.map