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
  generateExchangePair,
  deriveExchangeSymKey,
  getMasterHash,
  generateEcdsaPair,
  signEcdsa,
  verifyEcdsa,
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
    const keyPair1 = await generateExchangePair();
    const keyPair2 = await generateExchangePair();
    const symKey1 = await deriveExchangeSymKey(
      keyPair1.publicKey,
      keyPair2.privateKey
    );
    const symKey2 = await deriveExchangeSymKey(
      keyPair2.publicKey,
      keyPair1.privateKey
    );
    expect(symKey1).toEqual(symKey2);
  });

  it("Test ECDSA Signing", async () => {
    const keyPair = await generateEcdsaPair();
    const signature = await signEcdsa(
      keyPair.privateKey,
      Buffer.from(originalText)
    );
    const verified = await verifyEcdsa(
      keyPair.publicKey,
      Buffer.from(originalText),
      signature
    );
    expect(verified).toEqual(true);
  });
});
