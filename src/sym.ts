import crypto from "crypto";

const algorithm = "aes-256-cbc";
const KEY_SIZE = 32;
const IV_LENGTH = 16;

export const generateSymKey = (): string => {
  const symKey = crypto.randomBytes(KEY_SIZE);
  return symKey.toString("base64");
};

export const symEncrypt = (sym_key: string, data: Buffer): string => {
  const hash = crypto.createHash("sha256");
  hash.update(sym_key);
  const keyBytes = hash.digest();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(algorithm, keyBytes, iv);
  const enc = [cipher.update(data)];
  enc.push(cipher.final());

  const encrypted_data = Buffer.concat(enc);
  const encrypted = Buffer.concat([iv, encrypted_data]);
  return encrypted.toString("base64");
};

export const symDecrypt = (sym_key: string, encrypted_data: string): Buffer => {
  const data_bytes = Buffer.from(encrypted_data, "base64");
  const iv = data_bytes.slice(0, IV_LENGTH);
  const hash = crypto.createHash("sha256");
  hash.update(sym_key);
  const keyBytes = hash.digest();
  const decipher = crypto.createDecipheriv(algorithm, keyBytes, iv);
  let res = decipher.update(data_bytes.slice(IV_LENGTH));
  res = Buffer.concat([res, decipher.final()]);
  return res;
};
