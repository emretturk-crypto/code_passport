"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EMPTY_PRESET = exports.WorkerPreset = void 0;
const config_1 = require("./config");
const LoadTaskFromExecutableFilePlugin_1 = require("./plugins/LoadTaskFromExecutableFilePlugin");
const LoadTaskFromJsPlugin_1 = require("./plugins/LoadTaskFromJsPlugin");
exports.WorkerPreset = {
    plugins: [LoadTaskFromJsPlugin_1.LoadTaskFromJsPlugin, LoadTaskFromExecutableFilePlugin_1.LoadTaskFromExecutableFilePlugin],
    worker: (0, config_1.makeWorkerPresetWorkerOptions)(),
};
exports.EMPTY_PRESET = Object.freeze({});
//# sourceMappingURL=preset.js.map