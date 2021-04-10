import crypto from "crypto";

export const getMasterHash = (master_key: string, password: string): string => {
  const salt = Buffer.from(password, "base64");
  const hash = crypto.scryptSync(master_key, salt, 32);
  return hash.toString("base64");
};
