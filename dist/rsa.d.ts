/// <reference types="node" />
export declare const generateRsaPair: () => {
    publicKey: string;
    privateKey: string;
};
export declare const rsaEncrypt: (publicKey: string, data: Buffer) => string;
export declare const rsaDecrypt: (privateKey: string, encrypted: string) => Buffer;
