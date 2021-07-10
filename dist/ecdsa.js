"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyEcdsa = exports.signEcdsa = exports.generateEcdsaPair = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const constants_1 = require("./constants");
const ECDSA_ALGORITHM = "ECDSA";
const NAMED_CURVE = "P-256";
const generateEcdsaPair = async () => {
    const keys = await crypto_1.default.subtle.generateKey({
        name: ECDSA_ALGORITHM,
        namedCurve: NAMED_CURVE,
    }, true, ["sign", "verify"]);
    const publicKey = await crypto_1.default.subtle.exportKey("spki", keys.publicKey);
    const privateKey = await crypto_1.default.subtle.exportKey("pkcs8", keys.privateKey);
    return {
        publicKey: Buffer.from(publicKey).toString("base64"),
        privateKey: Buffer.from(privateKey).toString("base64"),
    };
};
exports.generateEcdsaPair = generateEcdsaPair;
const importEcdsaKey = (format, key, keyUsages) => crypto_1.default.subtle.importKey(format, Uint8Array.from(Buffer.from(key, "base64")), {
    name: ECDSA_ALGORITHM,
    namedCurve: NAMED_CURVE,
}, false, keyUsages);
const signEcdsa = async (private_key, data) => {
    const privateKey = await importEcdsaKey("pkcs8", private_key, ["sign"]);
    const signature = await window.crypto.subtle.sign({
        name: "ECDSA",
        hash: { name: constants_1.HASH_ALGORITHM },
    }, privateKey, data);
    return Buffer.from(signature).toString("base64");
};
exports.signEcdsa = signEcdsa;
const verifyEcdsa = async (public_key, data, signature) => {
    const publicKey = await importEcdsaKey("spki", public_key, ["verify"]);
    const verified = await window.crypto.subtle.verify({
        name: "ECDSA",
        hash: { name: constants_1.HASH_ALGORITHM },
    }, publicKey, Buffer.from(signature, "base64"), data);
    return verified;
};
exports.verifyEcdsa = verifyEcdsa;
//# sourceMappingURL=ecdsa.js.map