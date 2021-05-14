import fs from "fs";
import "../src/setupNodePollyfill";
import {
  getMasterKey,
  getEncryptionKey,
  symDecrypt,
  rsaDecrypt,
  deriveExchangeSymKey,
  getMasterHash,
} from "../src";
import { ExampleFile } from "./Example";

const originalText = "Hello";

describe("Example generated file", () => {
  const jsonDump = fs.readFileSync("./test/generateExample.json", "utf8");
  expect(jsonDump).not.toBeNull();
  const json: ExampleFile = JSON.parse(jsonDump);
  it("Test Master hashes", async () => {
    const masterKey = await getMasterKey(json.email, json.password);
    expect(masterKey).toEqual(json.masterKey);
    const masterHash = await getMasterHash(masterKey, json.password);
    expect(masterHash).toEqual(json.masterHash);
    const encryptionKey = await getEncryptionKey(masterKey);
    expect(encryptionKey).toEqual(json.encryptionKey);
  });

  it("Test symmetric key", async () => {
    const masterKey = await getMasterKey(json.email, json.password);
    const encryptionKey = await getEncryptionKey(masterKey);
    const decryptedSymKey = await symDecrypt(
      encryptionKey,
      json.sym.encryptedSymKey
    );
    const decryptedMessage = await symDecrypt(
      decryptedSymKey.toString("base64"),
      json.sym.encryptedSymMessage
    );
    expect(decryptedMessage.toString("utf-8")).toEqual(originalText);
  });

  it("Test rsa key", async () => {
    const masterKey = await getMasterKey(json.email, json.password);
    const encryptionKey = await getEncryptionKey(masterKey);
    const decryptedRsaPrivateKey = await symDecrypt(
      encryptionKey,
      json.rsa.encryptedPrivateKey
    );
    const decryptedMessage = await rsaDecrypt(
      decryptedRsaPrivateKey.toString("base64"),
      json.rsa.encryptedRsaMessage
    );
    expect(decryptedMessage.toString("utf-8")).toEqual(originalText);
  });

  it("Test ecdh key", async () => {
    const masterKey = await getMasterKey(json.email, json.password);
    const encryptionKey = await getEncryptionKey(masterKey);
    const decryptedEcdhPrivateKey1 = await symDecrypt(
      encryptionKey,
      json.ecdh.keys[0].encryptedPrivateKey
    );
    const derivedKey1 = await deriveExchangeSymKey(
      json.ecdh.keys[1].publicKey,
      decryptedEcdhPrivateKey1.toString("base64")
    );
    const decryptedEcdhPrivateKey2 = await symDecrypt(
      encryptionKey,
      json.ecdh.keys[1].encryptedPrivateKey
    );
    const derivedKey2 = await deriveExchangeSymKey(
      json.ecdh.keys[0].publicKey,
      decryptedEcdhPrivateKey2.toString("base64")
    );
    const edchDerivedKey = await symDecrypt(
      encryptionKey,
      json.ecdh.ecdhEncryptedSymKey
    );
    expect(derivedKey1).toEqual(derivedKey2);
    expect(edchDerivedKey.toString("base64")).toEqual(derivedKey1);
    const decryptedEcdhMessage = await symDecrypt(
      derivedKey1,
      json.ecdh.ecdhDerivedKeyMessage
    );
    expect(decryptedEcdhMessage.toString("utf-8")).toEqual(originalText);
  });
});
