import crypto from "crypto";

export const aesEncrypt = (
  encryption_key: string,
  encryption_mac: string,
  data: Buffer
): string => {
  const hash = crypto.createHash("sha256");
  hash.update(encryption_key);
  const keyBytes = hash.digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cfb", keyBytes, iv);
  const enc = [cipher.update(data)];
  enc.push(cipher.final());

  const encrypted_data = Buffer.concat(enc);
  const hmac = crypto.createHmac("sha256", encryption_mac);
  hmac.update(Buffer.concat([iv, encrypted_data]));
  const encrypted = Buffer.concat([hmac.digest(), iv, encrypted_data]);
  return encrypted.toString("base64");
};

export const aesDecrypt = (
  encryption_key: string,
  encryption_mac: string,
  data: string
): { isVerified: false } | { isVerified: true; data: Buffer } => {
  const hmac = crypto.createHmac("sha256", encryption_mac);
  const data_bytes = Buffer.from(data, "base64");
  const verify = data_bytes.slice(0, 32);
  hmac.update(data_bytes.slice(32));
  if (Buffer.compare(hmac.digest(), verify) !== 0) {
    return {
      isVerified: false,
    };
  }
  const iv = data_bytes.slice(32, 48);
  const hash = crypto.createHash("sha256");
  hash.update(encryption_key);
  const keyBytes = hash.digest();
  const decipher = crypto.createDecipheriv("aes-256-cfb", keyBytes, iv);
  let res = decipher.update(data_bytes.slice(48));
  res = Buffer.concat([res, decipher.final()]);
  return { isVerified: true, data: res };
};
