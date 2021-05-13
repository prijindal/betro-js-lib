"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveEcdhSymKey = exports.generateEcdhPair = void 0;
const crypto_1 = __importDefault(require("./crypto"));
const ECDH_ALGORITHM = "ECDH";
const NAMED_CURVE = "P-256";
const generateEcdhPair = async () => {
    const keys = await crypto_1.default.subtle.generateKey({
        name: ECDH_ALGORITHM,
        namedCurve: NAMED_CURVE,
    }, true, ["deriveKey"]);
    const publicKey = await crypto_1.default.subtle.exportKey("spki", keys.publicKey);
    const privateKey = await crypto_1.default.subtle.exportKey("pkcs8", keys.privateKey);
    return {
        publicKey: Buffer.from(publicKey).toString("base64"),
        privateKey: Buffer.from(privateKey).toString("base64"),
    };
};
exports.generateEcdhPair = generateEcdhPair;
const importEcdhKey = (format, key) => crypto_1.default.subtle.importKey(format, Buffer.from(key, "base64"), {
    name: ECDH_ALGORITHM,
    namedCurve: NAMED_CURVE,
}, false, ["deriveKey"]);
const deriveEcdhSymKey = async (public_key, private_key) => {
    const publicKey = await importEcdhKey("spki", public_key);
    const privateKey = await importEcdhKey("pkcs8", private_key);
    const keyData = await window.crypto.subtle.deriveKey({
        name: ECDH_ALGORITHM,
        //   namedCurve: NAMED_CURVE, //can be "P-256", "P-384", or "P-521"
        public: publicKey, //an ECDH public key from generateKey or importKey
    }, privateKey, //your ECDH private key from generateKey or importKey
    {
        //the key type you want to create based on the derived bits
        name: "AES-CBC",
        //the generateKey parameters for that type of algorithm
        length: 256, //can be  128, 192, or 256
    }, true, //whether the derived key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"] //limited to the options in that algorithm's importKey
    );
    const macData = await window.crypto.subtle.deriveKey({
        name: ECDH_ALGORITHM,
        //   namedCurve: NAMED_CURVE, //can be "P-256", "P-384", or "P-521"
        public: publicKey, //an ECDH public key from generateKey or importKey
    }, privateKey, //your ECDH private key from generateKey or importKey
    {
        //the key type you want to create based on the derived bits
        name: "HMAC",
        //the generateKey parameters for that type of algorithm
        hash: { name: "SHA-256" },
        length: 256, //can be  128, 192, or 256
    }, true, //whether the derived key is extractable (i.e. can be used in exportKey)
    ["sign", "verify"] //limited to the options in that algorithm's importKey
    );
    const rawKey = await crypto_1.default.subtle.exportKey("raw", keyData);
    const rawMac = await crypto_1.default.subtle.exportKey("raw", macData);
    return Buffer.concat([Buffer.from(rawKey), Buffer.from(rawMac)]).toString("base64");
};
exports.deriveEcdhSymKey = deriveEcdhSymKey;
//# sourceMappingURL=ecdh.js.map