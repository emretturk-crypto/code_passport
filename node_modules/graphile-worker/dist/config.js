"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeWorkerPresetWorkerOptions = void 0;
const cosmiconfig_1 = require("cosmiconfig");
const cronConstants_1 = require("./cronConstants");
const logger_1 = require("./logger");
const cosmiconfigResult = (0, cosmiconfig_1.cosmiconfigSync)("graphile-worker").search();
const cosmiconfig = cosmiconfigResult?.config;
/**
 * Defaults to use for various options throughout the codebase, sourced from
 * environmental variables, cosmiconfig, and finally sensible defaults.
 */
const makeWorkerPresetWorkerOptions = () => ({
    connectionString: process.env.DATABASE_URL,
    schema: process.env.GRAPHILE_WORKER_SCHEMA ||
        enforceStringOrUndefined("schema", cosmiconfig?.schema) ||
        "graphile_worker",
    pollInterval: enforceNumberOrUndefined("pollInterval", cosmiconfig?.pollInterval) ||
        2000,
    concurrentJobs: enforceNumberOrUndefined("concurrentJobs", cosmiconfig?.concurrentJobs) ||
        1,
    maxPoolSize: enforceNumberOrUndefined("maxPoolSize", cosmiconfig?.maxPoolSize) || 10,
    preparedStatements: true,
    crontabFile: `${process.cwd()}/crontab`,
    taskDirectory: `${process.cwd()}/tasks`,
    fileExtensions: [".js", ".cjs", ".mjs"],
    logger: logger_1.defaultLogger,
    minResetLockedInterval: 8 * cronConstants_1.MINUTE,
    maxResetLockedInterval: 10 * cronConstants_1.MINUTE,
    gracefulShutdownAbortTimeout: 5 * cronConstants_1.SECOND,
    useNodeTime: false,
});
exports.makeWorkerPresetWorkerOptions = makeWorkerPresetWorkerOptions;
function enforceStringOrUndefined(keyName, str) {
    if (typeof str === "string") {
        return str;
    }
    else if (!str) {
        return undefined;
    }
    else {
        throw new Error(`Expected '${keyName}' to be a string (or not set), but received ${typeof str}`);
    }
}
function enforceNumberOrUndefined(keyName, nr) {
    if (typeof nr === "number") {
        return nr;
    }
    else if (typeof nr === "string") {
        const val = parseFloat(nr);
        if (isFinite(val)) {
            return val;
        }
        else {
            throw new Error(`Expected '${keyName}' to be a number (or not set), but received ${nr}`);
        }
    }
    else if (!nr) {
        return undefined;
    }
    else {
        throw new Error(`Expected '${keyName}' to be a number (or not set), but received ${typeof nr}`);
    }
}
//# sourceMappingURL=config.js.map