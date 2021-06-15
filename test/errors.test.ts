import "../src/setupNodePollyfill";
import {
  getMasterKey,
  getEncryptionKey,
  generateSymKey,
  symDecrypt,
  symEncrypt,
  generateRsaPair,
  rsaDecrypt,
  rsaEncrypt,
  getMasterHash,
} from "../src";

const originalText = "Hello";

describe("Crypto Errors", () => {
  it("Test AES wrong encryption", async () => {
    const master_key = await getMasterKey("user@example.com", "123456");
    const encryption_key = await getEncryptionKey(master_key);
    const master_hash = await getMasterHash(master_key, "123456");
    expect(master_hash).toBeTruthy();

    const encryptedData = await symEncrypt(
      encryption_key,
      Buffer.from(originalText)
    );

    const new_master_key = await getMasterKey("user1@example.com", "123456");
    const newKey = await getEncryptionKey(new_master_key);

    const decrypted = await symDecrypt(newKey, encryptedData);
    expect(decrypted).toBeNull();
  });

  it("Test Sym key wrong encryption", async () => {
    const symKey = await generateSymKey();

    const symEncrypted = await symEncrypt(symKey, Buffer.from(originalText));

    const newKey = await generateSymKey();

    const symDecrypted = await symDecrypt(newKey, symEncrypted);
    expect(symDecrypted).toBeNull();
  });

  it("Test rsa key wrong encryption", async () => {
    const { publicKey, privateKey } = await generateRsaPair();

    const rsaEncrypted = await rsaEncrypt(publicKey, Buffer.from(originalText));

    const newKeys = await generateRsaPair();

    const rsaDecrypted = await rsaDecrypt(newKeys.privateKey, rsaEncrypted);
    expect(rsaDecrypted).toBeNull();
  });
});
