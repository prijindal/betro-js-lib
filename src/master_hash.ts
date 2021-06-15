import crypto from "./crypto";
import { HASH_ALGORITHM, HASH_LENGTH, ITERATIONS } from "./constants";

export const getMasterHash = async (
  master_key: string,
  password: string
): Promise<string> => {
  const salt = Buffer.from(password);
  const key = await crypto.subtle.importKey(
    "raw", // only raw format
    Buffer.from(master_key), // BufferSource
    "PBKDF2",
    false, // only false
    ["deriveBits", "deriveKey"]
  );
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
