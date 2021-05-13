import crypto from "./crypto";
const HMAC_ALGORITHM = {
    name: "HMAC",
    hash: "SHA-256",
};
const algorithm = "AES-CBC";
const KEY_SIZE = 256;
const IV_LENGTH = 16;
export const generateSymKey = async () => {
    const [key, hmac] = await Promise.all([
        crypto.subtle.generateKey({
            name: algorithm,
            length: KEY_SIZE,
        }, true, ["encrypt", "decrypt"]),
        window.crypto.subtle.generateKey(HMAC_ALGORITHM, true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"] //can be any combination of "sign" and "verify"
        ),
    ]);
    const [raw, rawHmac] = await Promise.all([
        crypto.subtle.exportKey("raw", key),
        crypto.subtle.exportKey("raw", hmac),
    ]);
    return Buffer.concat([Buffer.from(raw), Buffer.from(rawHmac)]).toString("base64");
};
const importKey = (key, keyUsage) => crypto.subtle.importKey("raw", key, algorithm, false, keyUsage);
const importHmac = (hmac, keyUsage) => crypto.subtle.importKey("raw", hmac, HMAC_ALGORITHM, false, keyUsage);
export const symEncrypt = async (sym_key, data) => {
    const buffer = Buffer.from(sym_key, "base64");
    const keyBuffer = buffer.slice(0, 32);
    const hmacBuffer = buffer.slice(32);
    const [key, hmac] = await Promise.all([
        importKey(keyBuffer, ["encrypt"]),
        importHmac(hmacBuffer, ["sign"]),
    ]);
    const iv = Buffer.from(crypto.getRandomValues(new Uint8Array(IV_LENGTH)));
    const encData = await crypto.subtle.encrypt({
        name: algorithm,
        iv,
    }, key, data);
    const encrypted_data = Buffer.from(encData);
    const signature = await crypto.subtle.sign("HMAC", hmac, Buffer.concat([iv, encrypted_data]));
    const encrypted = Buffer.concat([Buffer.from(signature), iv, encrypted_data]);
    return encrypted.toString("base64");
};
export const symDecrypt = async (sym_key, encrypted_data) => {
    const buffer = Buffer.from(sym_key, "base64");
    const keyBuffer = buffer.slice(0, 32);
    const hmacBuffer = buffer.slice(32);
    const [key, hmac] = await Promise.all([
        importKey(keyBuffer, ["decrypt"]),
        importHmac(hmacBuffer, ["verify"]),
    ]);
    const data_bytes = Buffer.from(encrypted_data, "base64");
    const iv = data_bytes.slice(32, 32 + IV_LENGTH);
    const isVerified = await crypto.subtle.verify("HMAC", hmac, data_bytes.slice(0, 32), data_bytes.slice(32));
    if (isVerified == false) {
        return null;
    }
    const data = await crypto.subtle.decrypt({
        name: algorithm,
        iv, // BufferSource
    }, key, // AES key
    data_bytes.slice(32 + IV_LENGTH) // BufferSource
    );
    return Buffer.from(data);
};
//# sourceMappingURL=sym.js.map