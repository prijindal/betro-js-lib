import crypto from "./crypto";
import { HASH_ALGORITHM } from "./constants";

const ECDSA_ALGORITHM = "ECDSA";

const NAMED_CURVE = "P-256";

export const generateEcdsaPair = async (): Promise<{
  publicKey: string;
  privateKey: string;
}> => {
  const keys = await crypto.subtle.generateKey(
    {
      name: ECDSA_ALGORITHM,
      namedCurve: NAMED_CURVE,
    },
    true,
    ["sign", "verify"]
  );
  const publicKey = await crypto.subtle.exportKey("spki", keys.publicKey);
  const privateKey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  return {
    publicKey: Buffer.from(publicKey).toString("base64"),
    privateKey: Buffer.from(privateKey).toString("base64"),
  };
};

const importEcdsaKey = (
  format: "spki" | "pkcs8",
  key: string,
  keyUsages: Array<"sign" | "verify">
) =>
  crypto.subtle.importKey(
    format,
    Uint8Array.from(Buffer.from(key, "base64")),
    {
      name: ECDSA_ALGORITHM,
      namedCurve: NAMED_CURVE,
    },
    false,
    keyUsages
  );

export const signEcdsa = async (
  private_key: string,
  data: Buffer
): Promise<string> => {
  const privateKey = await importEcdsaKey("pkcs8", private_key, ["sign"]);
  const signature = await window.crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: HASH_ALGORITHM },
    },
    privateKey,
    data
  );
  return Buffer.from(signature).toString("base64");
};

export const verifyEcdsa = async (
  public_key: string,
  data: Buffer,
  signature: string
): Promise<boolean> => {
  const publicKey = await importEcdsaKey("spki", public_key, ["verify"]);
  const verified = await window.crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: HASH_ALGORITHM },
    },
    publicKey,
    Buffer.from(signature, "base64"),
    data
  );
  return verified;
};
