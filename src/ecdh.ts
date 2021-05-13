import crypto from "./crypto";
// import { sharedKey, generateKeyPair } from "curve25519-js";
// import { getEncryptionKey } from "./get_key";

// export const generateExchangePair = async (): Promise<{
//   publicKey: string;
//   privateKey: string;
// }> => {
//   const seed = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
//   const keys = generateKeyPair(seed);
//   return {
//     publicKey: Buffer.from(keys.public).toString("base64"),
//     privateKey: Buffer.from(keys.private).toString("base64"),
//   };
// };

// export const deriveExchangeSymKey = async (
//   public_key: string,
//   private_key: string
// ): Promise<string> => {
//   const publicKey = Uint8Array.from(Buffer.from(public_key, "base64"));
//   const privateKey = Uint8Array.from(Buffer.from(private_key, "base64"));
//   const secret = sharedKey(privateKey, publicKey);
//   return getEncryptionKey(Buffer.from(secret).toString("base64"));
// };

const ECDH_ALGORITHM = "ECDH";

const NAMED_CURVE = "P-256";

export const generateExchangePair = async (): Promise<{
  publicKey: string;
  privateKey: string;
}> => {
  // const seed = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
  // const keys = generateKeyPair(seed);
  const keys = await crypto.subtle.generateKey(
    {
      name: ECDH_ALGORITHM,
      namedCurve: NAMED_CURVE,
    },
    true,
    ["deriveKey"]
  );
  const publicKey = await crypto.subtle.exportKey("spki", keys.publicKey);
  const privateKey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  console.log(Buffer.from(publicKey).length);
  return {
    publicKey: Buffer.from(publicKey).toString("base64"),
    privateKey: Buffer.from(privateKey).toString("base64"),
  };
};

const importEcdhKey = (format: "spki" | "pkcs8", key: string) =>
  crypto.subtle.importKey(
    format,
    Buffer.from(key, "base64"),
    {
      name: ECDH_ALGORITHM,
      namedCurve: NAMED_CURVE,
    },
    false,
    ["deriveKey"]
  );

export const deriveExchangeSymKey = async (
  public_key: string,
  private_key: string
): Promise<string> => {
  const publicKey = await importEcdhKey("spki", public_key);
  const privateKey = await importEcdhKey("pkcs8", private_key);
  const keyData = await window.crypto.subtle.deriveKey(
    {
      name: ECDH_ALGORITHM,
      //   namedCurve: NAMED_CURVE, //can be "P-256", "P-384", or "P-521"
      public: publicKey, //an ECDH public key from generateKey or importKey
    },
    privateKey, //your ECDH private key from generateKey or importKey
    {
      //the key type you want to create based on the derived bits
      name: "AES-CBC", //can be any AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH", or "HMAC")
      //the generateKey parameters for that type of algorithm
      length: 256, //can be  128, 192, or 256
    },
    true, //whether the derived key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"] //limited to the options in that algorithm's importKey
  );
  const macData = await window.crypto.subtle.deriveKey(
    {
      name: ECDH_ALGORITHM,
      //   namedCurve: NAMED_CURVE, //can be "P-256", "P-384", or "P-521"
      public: publicKey, //an ECDH public key from generateKey or importKey
    },
    privateKey, //your ECDH private key from generateKey or importKey
    {
      //the key type you want to create based on the derived bits
      name: "HMAC", //can be any AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH", or "HMAC")
      //the generateKey parameters for that type of algorithm
      hash: { name: "SHA-256" },
      length: 256, //can be  128, 192, or 256
    },
    true, //whether the derived key is extractable (i.e. can be used in exportKey)
    ["sign", "verify"] //limited to the options in that algorithm's importKey
  );
  const rawKey = await crypto.subtle.exportKey("raw", keyData);
  const rawMac = await crypto.subtle.exportKey("raw", macData);
  return Buffer.concat([Buffer.from(rawKey), Buffer.from(rawMac)]).toString(
    "base64"
  );
};
