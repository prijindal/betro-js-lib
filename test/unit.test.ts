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
  generateEcdhPair,
  deriveEcdhSymKey,
  getMasterHash,
} from "../src";

const originalText = "Hello";

describe("Crypto functions", () => {
  it("Test AES", async () => {
    const master_key = await getMasterKey("user@example.com", "123456");
    const encryption_key = await getEncryptionKey(master_key);
    const master_hash = await getMasterHash(master_key, "123456");
    expect(master_hash).toBeTruthy();

    const encryptedData = await symEncrypt(
      encryption_key,
      Buffer.from(originalText)
    );

    const decrypted = await symDecrypt(encryption_key, encryptedData);
    expect(decrypted).not.toBeNull();
    expect(decrypted.toString()).toEqual(originalText);
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

  it("Test ECDH algorithm", async () => {
    const keyPair1 = await generateEcdhPair();
    const keyPair2 = await generateEcdhPair();
    const symKey1 = await deriveEcdhSymKey(
      keyPair1.publicKey,
      keyPair2.privateKey
    );
    const symKey2 = await deriveEcdhSymKey(
      keyPair2.publicKey,
      keyPair1.privateKey
    );
    expect(symKey1).toEqual(symKey2);
  });
});
