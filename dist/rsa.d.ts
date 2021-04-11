/// <reference types="node" />
export declare const generateRsaPair: () => Promise<{
    publicKey: string;
    privateKey: string;
}>;
export declare const rsaEncrypt: (public_key: string, data: Buffer) => Promise<string>;
export declare const rsaDecrypt: (private_key: string, encrypted: string) => Promise<Buffer>;
