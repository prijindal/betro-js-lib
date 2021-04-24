/// <reference types="node" />
export declare const generateSymKey: () => Promise<string>;
export declare const symEncrypt: (sym_key: string, data: Buffer) => Promise<string>;
export declare const symDecrypt: (sym_key: string, encrypted_data: string) => Promise<Buffer | null>;
