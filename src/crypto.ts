const subtle = window.crypto.subtle;
const getRandomValues = <
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

const moduleCrypto: Crypto = {
  subtle,
  getRandomValues,
};

export default moduleCrypto;
