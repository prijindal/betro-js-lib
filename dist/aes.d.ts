/// <reference types="node" />
export declare const aesEncrypt: (encryption_key: string, encryption_mac: string, data: Buffer) => Promise<string>;
export declare const aesDecrypt: (encryption_key: string, encryption_mac: string, encrypted_data: string) => Promise<{
    isVerified: boolean;
    data: Buffer;
}>;
