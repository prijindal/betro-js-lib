import { Crypto } from "@peculiar/webcrypto";
const crypto = new Crypto();

const algorithm = "AES-CBC";
const KEY_SIZE = 256;
const IV_LENGTH = 16;

export const generateSymKey = async (): Promise<string> => {
  const key = await crypto.subtle.generateKey(
    {
      name: algorithm,
      length: KEY_SIZE,
    },
    true,
    ["encrypt"]
  );
  const raw = await crypto.subtle.exportKey("raw", key);
  return Buffer.from(raw).toString("base64");
};

export const symEncrypt = async (
  sym_key: string,
  data: Buffer
): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    Buffer.from(sym_key, "base64"),
    algorithm,
    false,
    ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encData = await crypto.subtle.encrypt(
    {
      name: algorithm,
      iv,
    },
    key,
    data
  );
  const encrypted_data = Buffer.from(encData);
  const encrypted = Buffer.concat([iv, encrypted_data]);
  return encrypted.toString("base64");
};

export const symDecrypt = async (
  sym_key: string,
  encrypted_data: string
): Promise<Buffer> => {
  const key = await crypto.subtle.importKey(
    "raw", // raw or jwk
    Buffer.from(sym_key, "base64"),
    algorithm,
    false, // extractable
    ["decrypt"]
  );
  const data_bytes = Buffer.from(encrypted_data, "base64");
  const iv = data_bytes.slice(0, IV_LENGTH);
  const data = await crypto.subtle.decrypt(
    {
      name: algorithm,
      iv, // BufferSource
    },
    key, // AES key
    data_bytes.slice(IV_LENGTH) // BufferSource
  );
  return Buffer.from(data);
};
