export declare const getMasterKey: (email: string, password: string) => string;
export declare const getEncryptionKey: (master_key: string) => {
    encryption_key: string;
    encryption_mac: string;
};
