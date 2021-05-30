if (typeof window !== "undefined" && window.crypto != undefined) {
}
else if (process.version.indexOf("v15") == 0 ||
    process.version.indexOf("v16") == 0) {
    const webcrypto = require("crypto").webcrypto;
    if (typeof window === "undefined") {
        global.window = {};
    }
    window.crypto = {
        subtle: webcrypto.subtle,
        getRandomValues: webcrypto.getRandomValues,
    };
}
else {
    const Crypto = require("@peculiar/webcrypto").Crypto;
    const crypto = new Crypto();
    if (typeof window === "undefined") {
        global.window = {};
    }
    window.crypto = {
        subtle: crypto.subtle,
        getRandomValues: crypto.getRandomValues,
    };
}
//# sourceMappingURL=setupNodePollyfill.js.map