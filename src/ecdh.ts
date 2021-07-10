import crypto from "./crypto";
import { hkdfDeriveAndExport } from "./get_key";

const ECDH_ALGORITHM = "ECDH";

const NAMED_CURVE = "P-256";

export const generateExchangePair = async (): Promise<{
  publicKey: string;
  privateKey: string;
}> => {
  const keys = await crypto.subtle.generateKey(
    {
      name: ECDH_ALGORITHM,
      namedCurve: NAMED_CURVE,
    },
    true,
    ["deriveBits"]
  );
  const publicKey = await crypto.subtle.exportKey("spki", keys.publicKey);
  const privateKey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  return {
    publicKey: Buffer.from(publicKey).toString("base64"),
    privateKey: Buffer.from(privateKey).toString("base64"),
  };
};

const importEcdhKey = (
  format: "spki" | "pkcs8",
  key: string,
  keyUsages: Array<"deriveBits">
) =>
  crypto.subtle.importKey(
    format,
    Uint8Array.from(Buffer.from(key, "base64")),
    {
      name: ECDH_ALGORITHM,
      namedCurve: NAMED_CURVE,
    },
    false,
    keyUsages
  );

export const deriveExchangeSymKey = async (
  public_key: string,
  private_key: string
): Promise<string> => {
  const [publicKey, privateKey] = await Promise.all([
    importEcdhKey("spki", public_key, []),
    importEcdhKey("pkcs8", private_key, ["deriveBits"]),
  ]);
  const keyData = await window.crypto.subtle.deriveBits(
    {
      name: ECDH_ALGORITHM,
      // namedCurve: NAMED_CURVE, //can be "P-256", "P-384", or "P-521"
      public: publicKey, //an ECDH public key from generateKey or importKey
    },
    privateKey, //your ECDH private key from generateKey or importKey
    256
  );
  const derivedKey = await crypto.subtle.importKey(
    "raw", // only raw format
    keyData, // BufferSource
    "HKDF",
    false, // only false
    ["deriveKey"]
  );
  const [key, mac] = await Promise.all([
    hkdfDeriveAndExport(derivedKey, "enc"),
    hkdfDeriveAndExport(derivedKey, "mac"),
  ]);
  return Buffer.concat([Buffer.from(key), Buffer.from(mac)]).toString("base64");
};
