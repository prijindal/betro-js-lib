import crypto from "./crypto";

const HMAC_ALGORITHM = {
  name: "HMAC",
  hash: "SHA-256",
};

const importAesKey = (key: string, keyUsage: KeyUsage[]) =>
  crypto.subtle.importKey(
    "raw",
    Buffer.from(key, "base64"),
    "AES-CBC",
    false,
    keyUsage
  );

const importHmacKey = (key: string, keyUsage: KeyUsage[]) =>
  crypto.subtle.importKey(
    "raw",
    Buffer.from(key, "base64"),
    HMAC_ALGORITHM,
    false,
    keyUsage
  );

export const aesEncrypt = async (
  encryption_key: string,
  encryption_mac: string,
  data: Buffer
): Promise<string> => {
  const key = await importAesKey(encryption_key, ["encrypt"]);
  const iv = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));
  const enc = await crypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv,
    },
    key,
    data
  );

  const encrypted_data = Buffer.from(enc);
  const hmac = await importHmacKey(encryption_mac, ["sign"]);
  const signature = await crypto.subtle.sign(
    "HMAC",
    hmac,
    Buffer.concat([iv, encrypted_data])
  );
  const encrypted = Buffer.concat([Buffer.from(signature), iv, encrypted_data]);
  return encrypted.toString("base64");
};

export const aesDecrypt = async (
  encryption_key: string,
  encryption_mac: string,
  encrypted_data: string
): Promise<{ isVerified: boolean; data: Buffer }> => {
  const data_bytes = Buffer.from(encrypted_data, "base64");
  const hmac = await importHmacKey(encryption_mac, ["verify"]);
  const isVerified = await crypto.subtle.verify(
    "HMAC",
    hmac,
    data_bytes.slice(0, 32),
    data_bytes.slice(32)
  );
  if (isVerified === false) {
    return {
      isVerified: isVerified,
      data: null,
    };
  }
  const key = await importAesKey(encryption_key, ["decrypt"]);
  const iv = data_bytes.slice(32, 48);
  const data = await crypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv,
    },
    key,
    data_bytes.slice(48)
  );
  return { isVerified: true, data: Buffer.from(data) };
};
