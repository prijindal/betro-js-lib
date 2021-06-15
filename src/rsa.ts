import crypto from "./crypto";
import { HASH_ALGORITHM } from "./constants";
const RSA_ALGORITHM = "RSA-OAEP";

const KEY_SIZE = 2048;

export const generateRsaPair = async (): Promise<{
  publicKey: string;
  privateKey: string;
}> => {
  const keys = await crypto.subtle.generateKey(
    {
      name: RSA_ALGORITHM,
      hash: HASH_ALGORITHM,
      publicExponent: new Uint8Array([1, 0, 1]), // 0x03 or 0x010001
      modulusLength: KEY_SIZE, // 1024, 2048, or 4096
    },
    true,
    ["encrypt", "decrypt"]
  );
  const publicKey = await crypto.subtle.exportKey("spki", keys.publicKey);
  const privateKey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  return {
    publicKey: Buffer.from(publicKey).toString("base64"),
    privateKey: Buffer.from(privateKey).toString("base64"),
  };
};

const importRsaKey = (
  format: "spki" | "pkcs8",
  key: string,
  keyUsage: KeyUsage[]
) =>
  crypto.subtle.importKey(
    format,
    Uint8Array.from(Buffer.from(key, "base64")),
    {
      name: RSA_ALGORITHM,
      hash: HASH_ALGORITHM,
    },
    false,
    keyUsage
  );

export const rsaEncrypt = async (
  public_key: string,
  data: Buffer
): Promise<string> => {
  const publicKey = await importRsaKey("spki", public_key, ["encrypt"]);
  const encData = await crypto.subtle.encrypt(
    {
      name: RSA_ALGORITHM,
    },
    publicKey, // RSA public key
    data // BufferSource
  );
  return Buffer.from(encData).toString("base64");
};

export const rsaDecrypt = async (
  private_key: string,
  encrypted: string
): Promise<Buffer | null> => {
  const privateKey = await importRsaKey("pkcs8", private_key, ["decrypt"]);
  try {
    const data = await crypto.subtle.decrypt(
      {
        name: RSA_ALGORITHM,
      },
      privateKey,
      Buffer.from(encrypted, "base64")
    );
    return Buffer.from(data);
  } catch (e) {
    return null;
  }
};
