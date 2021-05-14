export type ExampleFile = {
  email: string;
  password: string;
  masterKey: string;
  encryptionKey: string;
  masterHash: string;
  sym: {
    encryptedSymKey: string;
    encryptedSymMessage: string;
  };
  rsa: {
    publicKey: string;
    encryptedPrivateKey: string;
    encryptedRsaMessage: string;
  };
  ecdh: {
    keys: [
      {
        publicKey: string;
        encryptedPrivateKey: string;
      },
      {
        publicKey: string;
        encryptedPrivateKey: string;
      }
    ];
    ecdhEncryptedSymKey: string;
    ecdhDerivedKeyMessage: string;
  };
};
