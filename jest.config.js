module.exports = {
  projects: [{
    globals: {
      "ts-jest": {
        tsconfig: "tsconfig.json",
      },
    },
    moduleFileExtensions: ["ts", "js"],
    transform: {
      "^.+\\.(ts|tsx)$": "ts-jest",
    },
    collectCoverageFrom: ["src/**/*.ts"],
    testMatch: ["**/test/**/*.test.(ts|js)", "**/src/**/*.test.(ts|js)"],
    testEnvironment: "jsdom",
    testTimeout: 5000,
  }, {
    globals: {
      "ts-jest": {
        tsconfig: "tsconfig.json",
      },
    },
    moduleFileExtensions: ["ts", "js"],
    transform: {
      "^.+\\.(ts|tsx)$": "ts-jest",
    },
    collectCoverageFrom: ["src/**/*.ts"],
    testMatch: ["**/test/**/*.test.(ts|js)", "**/src/**/*.test.(ts|js)"],
    testEnvironment: "node",
    testTimeout: 5000,
  }]
};
