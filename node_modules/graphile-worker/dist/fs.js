"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.tryStat = void 0;
const promises_1 = require("fs/promises");
async function tryStat(pathToStat) {
    try {
        return await (0, promises_1.stat)(pathToStat);
    }
    catch (e) {
        return null;
    }
}
exports.tryStat = tryStat;
//# sourceMappingURL=fs.js.map