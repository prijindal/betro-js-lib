import crypto from "crypto";
import hkdf from "futoin-hkdf";

const HASH_LENGTH = 64;
const KEY_LENGTH = 32;

export const getMasterKey = (email: string, password: string): string => {
  const salt = Buffer.from(email, "base64");
  const hash = crypto.scryptSync(password, salt, KEY_LENGTH);
  return hash.toString("base64");
};

export const getEncryptionKey = (
  master_key: string
): { encryption_key: string; encryption_mac: string } => {
  const hkdf_prk = hkdf.extract("sha256", HASH_LENGTH, master_key, "sign");
  const encryption_key = hkdf
    .expand("sha256", HASH_LENGTH, hkdf_prk, KEY_LENGTH, "enc")
    .toString("base64");
  const encryption_mac = hkdf
    .expand("sha256", HASH_LENGTH, hkdf_prk, KEY_LENGTH, "mac")
    .toString("base64");
  return {
    encryption_key,
    encryption_mac,
  };
};
