"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const subtle = window.crypto.subtle;
const getRandomValues = (v) => {
    return window.crypto.getRandomValues(v);
};
const moduleCrypto = {
    subtle,
    getRandomValues,
};
exports.default = moduleCrypto;
//# sourceMappingURL=crypto.js.map