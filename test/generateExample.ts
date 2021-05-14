import fs from "fs";
import "../src/setupNodePollyfill";
import {
  getMasterKey,
  getEncryptionKey,
  generateSymKey,
  symEncrypt,
  generateRsaPair,
  rsaEncrypt,
  generateExchangePair,
  deriveExchangeSymKey,
  getMasterHash,
} from "../src";
import { ExampleFile } from "./Example";

const originalText = "Hello";

const generateExampleJson = async () => {
  const email = "user2@example.com";
  const password = "123456";
  const masterKey = await getMasterKey(email, password);
  const encryptionKey = await getEncryptionKey(masterKey);
  const masterHash = await getMasterHash(masterKey, password);

  const symKey = await generateSymKey();
  const encryptedSymKey = await symEncrypt(
    encryptionKey,
    Buffer.from(symKey, "base64")
  );
  const encryptedSymMessage = await symEncrypt(
    symKey,
    Buffer.from(originalText, "utf-8")
  );

  const rsaKeys = await generateRsaPair();
  const encryptedRsaPrivateKey = await symEncrypt(
    encryptionKey,
    Buffer.from(rsaKeys.privateKey, "base64")
  );
  const encryptedRsaMessage = await rsaEncrypt(
    rsaKeys.publicKey,
    Buffer.from(originalText, "utf-8")
  );

  const ecdhPair1 = await generateExchangePair();
  const ecdhPair2 = await generateExchangePair();
  const ecdhDerivedKey = await deriveExchangeSymKey(
    ecdhPair1.publicKey,
    ecdhPair2.privateKey
  );

  const ecdhDerivedKeyMessage = await symEncrypt(
    ecdhDerivedKey,
    Buffer.from(originalText, "utf-8")
  );

  const encryptedEcdhPrivateKey1 = await symEncrypt(
    encryptionKey,
    Buffer.from(ecdhPair1.privateKey, "base64")
  );
  const encryptedEcdhPrivateKey2 = await symEncrypt(
    encryptionKey,
    Buffer.from(ecdhPair2.privateKey, "base64")
  );
  const ecdhEncryptedSymKey = await symEncrypt(
    encryptionKey,
    Buffer.from(ecdhDerivedKey, "base64")
  );

  const json: ExampleFile = {
    email,
    password,
    masterKey,
    encryptionKey,
    masterHash,
    sym: {
      encryptedSymKey,
      encryptedSymMessage,
    },
    rsa: {
      publicKey: rsaKeys.publicKey,
      encryptedPrivateKey: encryptedRsaPrivateKey,
      encryptedRsaMessage,
    },
    ecdh: {
      keys: [
        {
          publicKey: ecdhPair1.publicKey,
          encryptedPrivateKey: encryptedEcdhPrivateKey1,
        },
        {
          publicKey: ecdhPair2.publicKey,
          encryptedPrivateKey: encryptedEcdhPrivateKey2,
        },
      ],
      ecdhEncryptedSymKey,
      ecdhDerivedKeyMessage,
    },
  };
  const jsonDump = JSON.stringify(json, null, 4);
  fs.writeFileSync("./test/generateExample.json", jsonDump);
};

generateExampleJson();
