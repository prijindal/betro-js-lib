export declare const getMasterKey: (email: string, password: string) => Promise<string>;
export declare const getEncryptionKey: (master_key: string) => Promise<string>;
