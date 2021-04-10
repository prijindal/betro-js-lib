"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMasterHash = void 0;
const crypto_1 = __importDefault(require("crypto"));
const getMasterHash = (master_key, password) => {
    const salt = Buffer.from(password, "base64");
    const hash = crypto_1.default.scryptSync(master_key, salt, 32);
    return hash.toString("base64");
};
exports.getMasterHash = getMasterHash;
//# sourceMappingURL=master_hash.js.map