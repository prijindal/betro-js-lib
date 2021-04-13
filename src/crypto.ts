let subtle: SubtleCrypto;
let getRandomValues;

if (typeof window !== "undefined" && window != null && window.crypto != null) {
  subtle = window.crypto.subtle;
  getRandomValues = <
    T extends
      | Int8Array
      | Int16Array
      | Int32Array
      | Uint8Array
      | Uint16Array
      | Uint32Array
      | Uint8ClampedArray
      | Float32Array
      | Float64Array
      | DataView
      | null
  >(
    v: T
  ): T => {
    return window.crypto.getRandomValues<T>(v);
  };
} else if (process.version.indexOf("v15") == 0) {
  const webcrypto = require("crypto").webcrypto;
  subtle = webcrypto.subtle;
  getRandomValues = webcrypto.getRandomValues;
} else {
  const Crypto = require("@peculiar/webcrypto").Crypto;
  const crypto = new Crypto();

  subtle = crypto.subtle;
  getRandomValues = crypto.getRandomValues;
}

const moduleCrypto: Crypto = {
  subtle,
  getRandomValues,
};

export default moduleCrypto;
