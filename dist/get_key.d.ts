export declare const getMasterKey: (email: string, password: string) => Promise<string>;
export declare const hkdfDeriveAndExport: (key: CryptoKey, info: string) => Promise<ArrayBuffer>;
export declare const getEncryptionKey: (master_key: string) => Promise<string>;
