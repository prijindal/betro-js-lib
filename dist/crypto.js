"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
let subtle;
let getRandomValues;
if (typeof window !== "undefined" && window != null && window.crypto != null) {
    subtle = window.crypto.subtle;
    getRandomValues = (v) => {
        return window.crypto.getRandomValues(v);
    };
}
else if (process.version.indexOf("v15") == 0) {
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
const moduleCrypto = {
    subtle,
    getRandomValues,
};
exports.default = moduleCrypto;
//# sourceMappingURL=crypto.js.map