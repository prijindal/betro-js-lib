/// <reference types="node" />
export declare const aesEncrypt: (encryption_key: string, encryption_mac: string, data: Buffer) => string;
export declare const aesDecrypt: (encryption_key: string, encryption_mac: string, data: string) => {
    isVerified: false;
} | {
    isVerified: true;
    data: Buffer;
};
