import crypto from "./crypto";

import { HASH_LENGTH, ITERATIONS, HASH_ALGORITHM } from "./constants";

const importKey = (key: Buffer, algorithm: string) =>
  crypto.subtle.importKey(
    "raw", // only raw format
    key, // BufferSource
    algorithm,
    false, // only false
    ["deriveBits", "deriveKey"]
  );

export const getMasterKey = async (
  email: string,
  password: string
): Promise<string> => {
  const salt = Buffer.from(email);
  const key = await importKey(Buffer.from(password), "PBKDF2");
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: HASH_ALGORITHM,
    },
    key,
    HASH_LENGTH
  );
  return Buffer.from(derivedBits).toString("base64");
};

const HKDF_ALGORITHM = {
  name: "HMAC",
  hash: HASH_ALGORITHM,
  length: HASH_LENGTH,
};

const hkdfParameters = (info: string) => ({
  name: "HKDF",
  salt: Buffer.from("sign"),
  info: Buffer.from(info),
  hash: HASH_ALGORITHM,
});

export const hkdfDeriveAndExport = async (
  key: CryptoKey,
  info: string
): Promise<ArrayBuffer> => {
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
  const key = await importKey(Buffer.from(master_key, "base64"), "HKDF");
  const encryption_key = await hkdfDeriveAndExport(key, "enc");
  const encryption_mac = await hkdfDeriveAndExport(key, "mac");
  return Buffer.concat([
    Buffer.from(encryption_key),
    Buffer.from(encryption_mac),
  ]).toString("base64");
};
