/// <reference types="node" />
export declare const generateSymKey: () => string;
export declare const symEncrypt: (sym_key: string, data: Buffer) => string;
export declare const symDecrypt: (sym_key: string, encrypted_data: string) => Buffer;
