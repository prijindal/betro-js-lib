import crypto from "./crypto";

import { HASH_LENGTH, ITERATIONS } from "./constants";

const importKey = (key: string, algorithm: string) =>
  crypto.subtle.importKey(
    "raw", // only raw format
    Buffer.from(key, "base64"), // BufferSource
    algorithm,
    false, // only false
    ["deriveBits", "deriveKey"]
  );

export const getMasterKey = async (
  email: string,
  password: string
): Promise<string> => {
  const salt = Buffer.from(email);
  const key = await importKey(password, "PBKDF2");
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256",
    },
    key,
    HASH_LENGTH
  );
  return Buffer.from(derivedBits).toString("base64");
};

const HKDF_ALGORITHM = {
  name: "HMAC",
  hash: "SHA-256",
  length: HASH_LENGTH,
};

const hkdfParameters = (info: string) => ({
  name: "HKDF",
  salt: Buffer.from("sign"),
  info: Buffer.from(info),
  hash: "SHA-256",
});

const hkdfDeriveAndExport = async (key: CryptoKey, info: string) => {
  const key_crypto = await crypto.subtle.deriveKey(
    hkdfParameters(info),
    key,
    HKDF_ALGORITHM,
    true,
    ["sign", "verify"]
  );
  const exported_key = await crypto.subtle.exportKey("raw", key_crypto);
  return exported_key;
};

export const getEncryptionKey = async (master_key: string): Promise<string> => {
  const key = await importKey(master_key, "HKDF");
  const encryption_key = await hkdfDeriveAndExport(key, "enc");
  const encryption_mac = await hkdfDeriveAndExport(key, "mac");
  return Buffer.concat([
    Buffer.from(encryption_key),
    Buffer.from(encryption_mac),
  ]).toString("base64");
};
