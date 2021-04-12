import crypto from "./crypto";

import { HASH_LENGTH, ITERATIONS } from "./constants";

export const getMasterKey = async (
  email: string,
  password: string
): Promise<string> => {
  const salt = Buffer.from(email);
  const key = await crypto.subtle.importKey(
    "raw", // only raw format
    Buffer.from(password), // BufferSource
    "PBKDF2",
    false, // only false
    ["deriveBits", "deriveKey"]
  );
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

export const getEncryptionKey = async (
  master_key: string
): Promise<{ encryption_key: string; encryption_mac: string }> => {
  const key = await crypto.subtle.importKey(
    "raw", // only raw format
    Buffer.from(master_key, "base64"), // BufferSource
    "HKDF",
    false, // only false
    ["deriveBits", "deriveKey"]
  );
  const encryption_key_crypto = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: Buffer.from("sign"),
      info: Buffer.from("enc"),
      hash: "SHA-256",
    },
    key,
    {
      name: "HMAC",
      hash: "SHA-256",
      length: HASH_LENGTH,
    },
    true,
    ["sign", "verify"]
  );
  const encryption_mac_crypto = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: Buffer.from("sign"),
      info: Buffer.from("mac"),
      hash: "SHA-256",
    },
    key,
    {
      name: "HMAC",
      hash: "SHA-256",
      length: HASH_LENGTH,
    },
    true,
    ["sign", "verify"]
  );
  const encryption_key = await crypto.subtle.exportKey(
    "raw",
    encryption_key_crypto
  );
  const encryption_mac = await crypto.subtle.exportKey(
    "raw",
    encryption_mac_crypto
  );
  return {
    encryption_key: Buffer.from(encryption_key).toString("base64"),
    encryption_mac: Buffer.from(encryption_mac).toString("base64"),
  };
};
