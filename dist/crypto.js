"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
let subtle;
let getRandomValues;
if (process.version.indexOf("v15") == 0) {
    const webcrypto = require("crypto").webcrypto;
    subtle = webcrypto.subtle;
    getRandomValues = webcrypto.getRandomValues;
}
else {
    const Crypto = require("@peculiar/webcrypto").Crypto;
    const crypto = new Crypto();
    subtle = crypto.subtle;
    getRandomValues = crypto.getRandomValues;
}
exports.default = {
    subtle,
    getRandomValues,
};
//# sourceMappingURL=crypto.js.map