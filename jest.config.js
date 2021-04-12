module.exports = {
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
};