import { getMasterKey, getEncryptionKey } from "../src/get_key";
import { aesDecrypt, aesEncrypt } from "../src/aes";
import { generateSymKey, symDecrypt, symEncrypt } from "../src/sym";
import { generateRsaPair, rsaDecrypt, rsaEncrypt } from "../src/rsa";

const originalText = "Hello";

describe("Crypto functions", () => {
  it("Test AES", () => {
    const master_key = getMasterKey("user@example.com", "123456");
    const { encryption_key, encryption_mac } = getEncryptionKey(master_key);

    const encryptedData = aesEncrypt(
      encryption_key,
      encryption_mac,
      Buffer.from(originalText)
    );

    const decrypted = aesDecrypt(encryption_key, encryption_mac, encryptedData);
    expect(decrypted.isVerified).toEqual(true);
    if (decrypted.isVerified) {
      expect(decrypted.data.toString()).toEqual(originalText);
    }
  });

  it("Test Sym key", () => {
    const symKey = generateSymKey();

    const symEncrypted = symEncrypt(symKey, Buffer.from(originalText));

    const symDecrypted = symDecrypt(symKey, symEncrypted);
    expect(symDecrypted.toString()).toEqual(originalText);
  });

  it("Test rsa key", () => {
    const { publicKey, privateKey } = generateRsaPair();

    const rsaDecrypted = rsaDecrypt(
      privateKey,
      rsaEncrypt(publicKey, Buffer.from(originalText))
    );
    expect(rsaDecrypted.toString()).toEqual(originalText);
  });
});
