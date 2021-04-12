let subtle: SubtleCrypto;
let getRandomValues;

if (typeof window != undefined && window != null && window.crypto != null) {
  subtle = window.crypto.subtle;
  getRandomValues = window.crypto.getRandomValues;
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

export default {
  subtle,
  getRandomValues,
};
