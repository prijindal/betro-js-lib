import crypto from "./crypto";
import { HASH_LENGTH, ITERATIONS } from "./constants";
const importKey = (key, algorithm) => crypto.subtle.importKey("raw", // only raw format
Buffer.from(key, "base64"), // BufferSource
algorithm, false, // only false
["deriveBits", "deriveKey"]);
export const getMasterKey = async (email, password) => {
    const salt = Buffer.from(email);
    const key = await importKey(password, "PBKDF2");
    const derivedBits = await crypto.subtle.deriveBits({
        name: "PBKDF2",
        salt,
        iterations: ITERATIONS,
        hash: "SHA-256",
    }, key, HASH_LENGTH);
    return Buffer.from(derivedBits).toString("base64");
};
const HKDF_ALGORITHM = {
    name: "HMAC",
    hash: "SHA-256",
    length: HASH_LENGTH,
};
const hkdfParameters = (info) => ({
    name: "HKDF",
    salt: Buffer.from("sign"),
    info: Buffer.from(info),
    hash: "SHA-256",
});
const hkdfDeriveAndExport = async (key, info) => {
    const key_crypto = await crypto.subtle.deriveKey(hkdfParameters(info), key, HKDF_ALGORITHM, true, ["sign", "verify"]);
    const exported_key = await crypto.subtle.exportKey("raw", key_crypto);
    return exported_key;
};
export const getEncryptionKey = async (master_key) => {
    const key = await importKey(master_key, "HKDF");
    const encryption_key = await hkdfDeriveAndExport(key, "enc");
    const encryption_mac = await hkdfDeriveAndExport(key, "mac");
    return Buffer.concat([
        Buffer.from(encryption_key),
        Buffer.from(encryption_mac),
    ]).toString("base64");
};
//# sourceMappingURL=get_key.js.map