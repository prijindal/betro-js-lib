export declare const generateEcdhPair: () => Promise<{
    publicKey: string;
    privateKey: string;
}>;
export declare const deriveEcdhSymKey: (public_key: string, private_key: string) => Promise<string>;
