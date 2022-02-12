export declare const generateEcdsaPair: () => Promise<{
    publicKey: string;
    privateKey: string;
}>;
export declare const signEcdsa: (private_key: string, data: Buffer) => Promise<string>;
export declare const verifyEcdsa: (public_key: string, data: Buffer, signature: string) => Promise<boolean>;
