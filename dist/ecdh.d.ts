export declare const generateExchangePair: () => Promise<{
  publicKey: string;
  privateKey: string;
}>;
export declare const deriveExchangeSymKey: (
  public_key: string,
  private_key: string
) => Promise<string>;
