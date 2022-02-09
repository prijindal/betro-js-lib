import "../src/setupNodePollyfill";
import {
  deriveExchangeSymKey,
  generateExchangePair,
  generateRsaPair,
  generateSymKey,
  rsaDecrypt,
  rsaEncrypt,
  symDecrypt,
  symEncrypt,
} from "../src";

if (global.performance == null) {
  global.performance = require("perf_hooks").performance;
}

const text = "Hello, this is a test script";

const rsaFunction = async () => {
  const rsaKeys = await generateRsaPair();
  const encrypted = await rsaEncrypt(
    rsaKeys.publicKey,
    Buffer.from(text, "utf-8")
  );
  const decrypted = await rsaDecrypt(rsaKeys.privateKey, encrypted);
  if (decrypted.toString("utf-8") !== text) {
    throw Error();
  }
};

const symFunction = async () => {
  const symKey = await generateSymKey();
  const encrypted = await symEncrypt(symKey, Buffer.from(text, "utf-8"));
  const decrypted = await symDecrypt(symKey, encrypted);
  if (decrypted.toString("utf-8") !== text) {
    throw Error();
  }
};

const exchangeFunction = async () => {
  const keyPair1 = await generateExchangePair();
  const keyPair2 = await generateExchangePair();
  const key1 = await deriveExchangeSymKey(
    keyPair1.publicKey,
    keyPair2.privateKey
  );
  const key2 = await deriveExchangeSymKey(
    keyPair2.publicKey,
    keyPair1.privateKey
  );
  if (key1 !== key2) {
    throw Error();
  }
};

const testPerformance = async (
  N: number,
  funct: () => Promise<void>
): Promise<number> => {
  const timer = performance.now();
  for (let index = 0; index < N; index++) {
    await funct();
  }
  const endTimer = performance.now();
  const diff = endTimer - timer;
  return diff / N;
};

describe("Crypto performance functions", () => {
  const performances = {
    rsa: Infinity,
    sym: Infinity,
    exchange: Infinity,
  };
  it("RSA Performance", async () => {
    const rsaPerformance = await testPerformance(100, rsaFunction);
    expect(rsaPerformance).toBeLessThan(400);
    performances.rsa = rsaPerformance;
  }, 20000);
  it("Sym Key Performance", async () => {
    const symPerformance = await testPerformance(100, symFunction);
    expect(symPerformance).toBeLessThan(400);
    performances.sym = symPerformance;
  }, 20000);
  it("Exchange Performance", async () => {
    const exchangePerformance = await testPerformance(100, exchangeFunction);
    expect(exchangePerformance).toBeLessThan(400);
    performances.exchange = exchangePerformance;
  }, 20000);
  afterAll(() => {
    console.log(`RSA Performance: ${performances.rsa}`);
    console.log(`Sym Key Performance: ${performances.sym}`);
    console.log(`Exchange Performance: ${performances.exchange}`);
  });
});
