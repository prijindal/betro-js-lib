import "../src/setupNodePollyfill";
import {
  getMasterKey,
  getEncryptionKey,
  aesDecrypt,
  aesEncrypt,
  generateSymKey,
  symDecrypt,
  symEncrypt,
  generateRsaPair,
  rsaDecrypt,
  rsaEncrypt,
  getMasterHash,
} from "../src";

const originalText = "Hello";

describe("Crypto functions", () => {
  it("Test AES", async () => {
    const master_key = await getMasterKey("user@example.com", "123456");
    const { encryption_key, encryption_mac } = await getEncryptionKey(
      master_key
    );
    const master_hash = await getMasterHash(master_key, "123456");
    expect(master_hash).toBeTruthy();

    const encryptedData = await aesEncrypt(
      encryption_key,
      encryption_mac,
      Buffer.from(originalText)
    );

    const decrypted = await aesDecrypt(
      encryption_key,
      encryption_mac,
      encryptedData
    );
    expect(decrypted.isVerified).toEqual(true);
    if (decrypted.isVerified) {
      expect(decrypted.data.toString()).toEqual(originalText);
    }
  });

  it("Test Sym key", async () => {
    const symKey = await generateSymKey();

    const symEncrypted = await symEncrypt(symKey, Buffer.from(originalText));

    const symDecrypted = await symDecrypt(symKey, symEncrypted);
    expect(symDecrypted.toString()).toEqual(originalText);
  });

  it("Test rsa key", async () => {
    const { publicKey, privateKey } = await generateRsaPair();

    const rsaEncrypted = await rsaEncrypt(publicKey, Buffer.from(originalText));

    const rsaDecrypted = await rsaDecrypt(privateKey, rsaEncrypted);
    expect(rsaDecrypted.toString()).toEqual(originalText);
  });
});
