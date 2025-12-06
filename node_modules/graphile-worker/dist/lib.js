"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sleep = exports.makeEnhancedWithPgClient = exports.tryParseJson = exports.getUtilsAndReleasersFromOptions = exports.withReleasers = exports.assertPool = exports.processSharedOptions = exports.BREAKING_MIGRATIONS = void 0;
const tslib_1 = require("tslib");
const assert = tslib_1.__importStar(require("assert"));
const events_1 = require("events");
const graphile_config_1 = require("graphile-config");
const pg_1 = require("pg");
const sql_1 = require("./generated/sql");
const helpers_1 = require("./helpers");
const migrate_1 = require("./migrate");
const preset_1 = require("./preset");
const version_1 = require("./version");
const MAX_MIGRATION_NUMBER = Object.keys(sql_1.migrations).reduce((memo, migrationFile) => {
    const migrationNumber = parseInt(migrationFile.slice(0, 6), 10);
    return Math.max(memo, migrationNumber);
}, 0);
exports.BREAKING_MIGRATIONS = Object.entries(sql_1.migrations)
    .filter(([_, text]) => {
    return text.startsWith("--! breaking");
})
    .map(([migrationFile]) => parseInt(migrationFile.slice(0, 6), 10));
/**
 * Important: ensure you still handle `forbiddenFlags`, `pgPool`, `workerId`,
 * `autostart`, `workerPool`, `abortSignal`, `noHandleSignals`, `taskList`,
 * `crontab`, `parsedCronItems`!
 */
function legacyOptionsToPreset(options) {
    if ("_rawOptions" in options) {
        console.trace("GraphileWorkerInternalError: CompiledSharedOptions used where SharedOptions was expected.");
        throw new Error("GraphileWorkerInternalError: CompiledSharedOptions used where SharedOptions was expected.");
    }
    assert.ok(!options.taskList || !options.taskDirectory, "Exactly one of either `taskDirectory` or `taskList` should be set");
    const preset = {
        extends: [],
        worker: {},
    };
    for (const key of Object.keys(options)) {
        if (options[key] == null) {
            continue;
        }
        switch (key) {
            case "forbiddenFlags":
            case "pgPool":
            case "workerId":
            case "autostart":
            case "workerPool":
            case "abortSignal":
            case "noHandleSignals":
            case "taskList":
            case "crontab":
            case "parsedCronItems": {
                // ignore
                break;
            }
            case "preset": {
                preset.extends.push(options[key]);
                break;
            }
            case "logger": {
                preset.worker.logger = options[key];
                break;
            }
            case "schema": {
                preset.worker.schema = options[key];
                break;
            }
            case "connectionString": {
                preset.worker.connectionString = options[key];
                break;
            }
            case "events": {
                preset.worker.events = options[key];
                break;
            }
            case "maxPoolSize": {
                preset.worker.maxPoolSize = options[key];
                break;
            }
            case "useNodeTime": {
                preset.worker.useNodeTime = options[key];
                break;
            }
            case "noPreparedStatements": {
                preset.worker.preparedStatements = !options[key];
                break;
            }
            case "minResetLockedInterval": {
                preset.worker.minResetLockedInterval = options[key];
                break;
            }
            case "maxResetLockedInterval": {
                preset.worker.maxResetLockedInterval = options[key];
                break;
            }
            case "gracefulShutdownAbortTimeout": {
                preset.worker.gracefulShutdownAbortTimeout = options[key];
                break;
            }
            case "pollInterval": {
                preset.worker.pollInterval = options[key];
                break;
            }
            case "concurrency": {
                preset.worker.concurrentJobs = options[key];
                break;
            }
            case "taskDirectory": {
                preset.worker.taskDirectory = options[key];
                break;
            }
            case "crontabFile": {
                preset.worker.crontabFile = options[key];
                break;
            }
            default: {
                const never = key;
                console.warn(`Do not know how to convert config option '${never}' into its preset equivalent; ignoring.`);
            }
        }
    }
    return preset;
}
const _sharedOptionsCache = new WeakMap();
function processSharedOptions(options, { scope } = {}) {
    if ("_rawOptions" in options) {
        throw new Error(`Fed processed options to processSharedOptions; this is invalid.`);
    }
    let compiled = _sharedOptionsCache.get(options);
    if (!compiled) {
        const resolvedPreset = (0, graphile_config_1.resolvePresets)([
            preset_1.WorkerPreset,
            // Explicit options override the preset
            legacyOptionsToPreset(options),
        ]);
        const { worker: { minResetLockedInterval, maxResetLockedInterval, schema: workerSchema, logger, events = new events_1.EventEmitter(), }, } = resolvedPreset;
        const escapedWorkerSchema = pg_1.Client.prototype.escapeIdentifier(workerSchema);
        if (!Number.isFinite(minResetLockedInterval) ||
            !Number.isFinite(maxResetLockedInterval) ||
            minResetLockedInterval < 1 ||
            maxResetLockedInterval < minResetLockedInterval) {
            throw new Error(`Invalid values for minResetLockedInterval (${minResetLockedInterval})/maxResetLockedInterval (${maxResetLockedInterval})`);
        }
        const hooks = new graphile_config_1.AsyncHooks();
        compiled = {
            version: version_1.version,
            maxMigrationNumber: MAX_MIGRATION_NUMBER,
            breakingMigrationNumbers: exports.BREAKING_MIGRATIONS,
            events,
            logger,
            workerSchema,
            escapedWorkerSchema,
            _rawOptions: options,
            hooks,
            resolvedPreset,
        };
        (0, graphile_config_1.applyHooks)(resolvedPreset.plugins, (p) => p.worker?.hooks, (name, fn, plugin) => {
            const context = compiled;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const cb = ((...args) => fn(context, ...args));
            cb.displayName = `${plugin.name}_hook_${name}`;
            hooks.hook(name, cb);
        });
        _sharedOptionsCache.set(options, compiled);
        Promise.resolve(hooks.process("init")).catch((error) => {
            logger.error(`One of the plugins you are using raised an error during 'init'; but errors during 'init' are currently ignored. Continuing. Error: ${error}`, { error });
        });
    }
    if (scope) {
        return {
            ...compiled,
            logger: compiled.logger.scope(scope),
        };
    }
    else {
        return compiled;
    }
}
exports.processSharedOptions = processSharedOptions;
async function assertPool(compiledSharedOptions, releasers) {
    const { logger, resolvedPreset: { worker: { maxPoolSize, connectionString }, }, _rawOptions, } = compiledSharedOptions;
    assert.ok(
    // NOTE: we explicitly want `_rawOptions.connectionString` here - we don't
    // mind if `connectionString` is set as part of the preset.
    !_rawOptions.pgPool || !_rawOptions.connectionString, "Both `pgPool` and `connectionString` are set, at most one of these options should be provided");
    let pgPool;
    if (_rawOptions.pgPool) {
        pgPool = _rawOptions.pgPool;
    }
    else if (connectionString) {
        pgPool = new pg_1.Pool({
            connectionString,
            max: maxPoolSize,
        });
        releasers.push(() => {
            pgPool.end();
        });
    }
    else if (process.env.PGDATABASE) {
        pgPool = new pg_1.Pool({
            /* Pool automatically pulls settings from envvars */
            max: maxPoolSize,
        });
        releasers.push(() => {
            pgPool.end();
        });
    }
    else {
        throw new Error("You must either specify `pgPool` or `connectionString`, or you must make the `DATABASE_URL` or `PG*` environmental variables available.");
    }
    const handlePoolError = (err) => {
        /*
         * This handler is required so that client connection errors on clients
         * that are alive but not checked out don't bring the server down (via
         * `unhandledError`).
         *
         * `pg` will automatically terminate the client and remove it from the
         * pool, so we don't actually need to take any action here, just ensure
         * that the event listener is registered.
         */
        logger.error(`PostgreSQL idle client generated error: ${err.message}`, {
            error: err,
        });
    };
    const handleClientError = (err) => {
        /*
         * This handler is required so that client connection errors on clients
         * that are checked out of the pool don't bring the server down (via
         * `unhandledError`).
         *
         * `pg` will automatically raise the error from the client the next time it
         * attempts a query, so we don't actually need to take any action here,
         * just ensure that the event listener is registered.
         */
        logger.error(`PostgreSQL active client generated error: ${err.message}`, {
            error: err,
        });
    };
    pgPool.on("error", handlePoolError);
    const handlePoolConnect = (client) => {
        client.on("error", handleClientError);
    };
    pgPool.on("connect", handlePoolConnect);
    releasers.push(() => {
        pgPool.removeListener("error", handlePoolError);
        pgPool.removeListener("connect", handlePoolConnect);
    });
    return pgPool;
}
exports.assertPool = assertPool;
async function withReleasers(callback) {
    const releasers = [];
    let released = false;
    const release = async () => {
        if (released) {
            throw new Error(`Internal error: compiledOptions was released twice.`);
        }
        else {
            released = true;
        }
        let firstError = null;
        // Call releasers in reverse order - LIFO queue.
        for (let i = releasers.length - 1; i >= 0; i--) {
            try {
                await releasers[i]();
            }
            catch (e) {
                firstError = firstError || e;
            }
        }
        if (firstError) {
            throw firstError;
        }
    };
    try {
        return await callback(releasers, release);
    }
    catch (e) {
        try {
            await release();
        }
        catch (e2) {
            /* noop */
        }
        throw e;
    }
}
exports.withReleasers = withReleasers;
const getUtilsAndReleasersFromOptions = async (options, settings = {}) => {
    if ("_rawOptions" in options) {
        throw new Error(`Fed processed options to getUtilsAndReleasersFromOptions; this is invalid.`);
    }
    const compiledSharedOptions = processSharedOptions(options, settings);
    const { logger, resolvedPreset: { worker: { concurrentJobs: concurrency }, }, } = compiledSharedOptions;
    return withReleasers(async function getUtilsFromOptions(releasers, release) {
        const pgPool = await assertPool(compiledSharedOptions, releasers);
        // @ts-ignore
        const max = pgPool?.options?.max || 10;
        if (max < concurrency) {
            logger.warn(`WARNING: having maxPoolSize (${max}) smaller than concurrency (${concurrency}) may lead to non-optimal performance.`, { max, concurrency });
        }
        const withPgClient = makeEnhancedWithPgClient((0, helpers_1.makeWithPgClientFromPool)(pgPool));
        // Migrate
        await withPgClient(function migrateWithPgClient(client) {
            return (0, migrate_1.migrate)(compiledSharedOptions, client);
        });
        const addJob = (0, helpers_1.makeAddJob)(compiledSharedOptions, withPgClient);
        return [
            {
                ...compiledSharedOptions,
                pgPool,
                withPgClient,
                addJob,
                releasers,
            },
            release,
        ];
    });
};
exports.getUtilsAndReleasersFromOptions = getUtilsAndReleasersFromOptions;
function tryParseJson(json) {
    if (json == null) {
        return null;
    }
    try {
        return JSON.parse(json);
    }
    catch (e) {
        return null;
    }
}
exports.tryParseJson = tryParseJson;
/** @see {@link https://www.postgresql.org/docs/current/mvcc-serialization-failure-handling.html} */
const RETRYABLE_ERROR_CODES = [
    { code: "40001", backoffMS: 50 },
    { code: "40P01", backoffMS: 50 },
    { code: "57P03", backoffMS: 3000 },
    { code: "EHOSTUNREACH", backoffMS: 3000 },
    { code: "ETIMEDOUT", backoffMS: 3000 }, // timeout
];
const MAX_RETRIES = 100;
function makeEnhancedWithPgClient(withPgClient) {
    if ("withRetries" in withPgClient &&
        typeof withPgClient.withRetries === "function") {
        return withPgClient;
    }
    const enhancedWithPgClient = withPgClient;
    enhancedWithPgClient.withRetries = async (...args) => {
        let lastError;
        for (let attempts = 0; attempts < MAX_RETRIES; attempts++) {
            try {
                return await withPgClient(...args);
            }
            catch (e) {
                const retryable = RETRYABLE_ERROR_CODES.find(({ code }) => code === e.code);
                if (retryable) {
                    lastError = e;
                    // Try again in backoffMS
                    await (0, exports.sleep)(retryable.backoffMS * Math.sqrt(attempts + 1));
                }
                else {
                    throw e;
                }
            }
        }
        console.error(`Retried ${MAX_RETRIES} times, and still failed:`, lastError);
        throw lastError;
    };
    return enhancedWithPgClient;
}
exports.makeEnhancedWithPgClient = makeEnhancedWithPgClient;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
exports.sleep = sleep;
//# sourceMappingURL=lib.js.map