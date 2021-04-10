import crypto from "crypto";

export const generateRsaPair = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });
  return { publicKey, privateKey };
};

export const rsaEncrypt = (publicKey: string, data: Buffer): string => {
  const encrypted = crypto.publicEncrypt(publicKey, data);
  return encrypted.toString("base64");
};

export const rsaDecrypt = (privateKey: string, encrypted: string): Buffer => {
  const buffer = Buffer.from(encrypted, "base64");
  const data = crypto.privateDecrypt(privateKey, buffer);
  return data;
};
