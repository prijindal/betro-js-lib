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
  generateEcdsaPair,
  signEcdsa,
  verifyEcdsa,
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

  it("Test ECDSA Wrong Signing", async () => {
    const keyPair1 = await generateEcdsaPair();
    const keyPair2 = await generateEcdsaPair();
    const signature = await signEcdsa(
      keyPair1.privateKey,
      Buffer.from(originalText)
    );
    const verified = await verifyEcdsa(
      keyPair2.publicKey,
      Buffer.from(originalText),
      signature
    );
    expect(verified).toEqual(false);
  });
});
