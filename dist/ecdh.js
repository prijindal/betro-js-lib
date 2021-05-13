import crypto from "./crypto";
const ECDH_ALGORITHM = "ECDH";
const NAMED_CURVE = "P-256";
export const generateEcdhPair = async () => {
    const keys = await crypto.subtle.generateKey({
        name: ECDH_ALGORITHM,
        namedCurve: NAMED_CURVE,
    }, true, ["deriveKey"]);
    const publicKey = await crypto.subtle.exportKey("spki", keys.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
    return {
        publicKey: Buffer.from(publicKey).toString("base64"),
        privateKey: Buffer.from(privateKey).toString("base64"),
    };
};
const importEcdhKey = (format, key) => crypto.subtle.importKey(format, Buffer.from(key, "base64"), {
    name: ECDH_ALGORITHM,
    namedCurve: NAMED_CURVE,
}, false, ["deriveKey"]);
export const deriveEcdhSymKey = async (public_key, private_key) => {
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
    const raw = await crypto.subtle.exportKey("raw", keyData);
    return Buffer.from(raw).toString("base64");
};
//# sourceMappingURL=ecdh.js.map