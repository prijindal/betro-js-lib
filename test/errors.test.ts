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
  it("Test AES wrong encryption", async () => {
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

    const new_master_key = await getMasterKey("user1@example.com", "123456");
    const newKeys = await getEncryptionKey(new_master_key);

    const decrypted = await aesDecrypt(
      newKeys.encryption_key,
      newKeys.encryption_mac,
      encryptedData
    );
    expect(decrypted.isVerified).toEqual(false);
    expect(decrypted.data).toBeNull();
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
