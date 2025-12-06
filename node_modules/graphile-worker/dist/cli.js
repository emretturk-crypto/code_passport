#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const load_1 = require("graphile-config/load");
const yargs = tslib_1.__importStar(require("yargs"));
const cleanup_1 = require("./cleanup");
const getCronItems_1 = require("./getCronItems");
const getTasks_1 = require("./getTasks");
const lib_1 = require("./lib");
const preset_1 = require("./preset");
const runner_1 = require("./runner");
const defaults = preset_1.WorkerPreset.worker;
const argv = yargs
    .parserConfiguration({
    "boolean-negation": false,
})
    .option("connection", {
    description: "Database connection string, defaults to the 'DATABASE_URL' envvar",
    alias: "c",
})
    .string("connection")
    .option("schema", {
    description: "The database schema in which Graphile Worker is (to be) located",
    alias: "s",
    default: defaults.schema,
})
    .string("schema")
    .option("schema-only", {
    description: "Just install (or update) the database schema, then exit",
    default: false,
})
    .boolean("schema-only")
    .option("once", {
    description: "Run until there are no runnable jobs left, then exit",
    default: false,
})
    .boolean("once")
    .option("crontab", {
    description: "override path to crontab file",
})
    .string("crontab")
    .option("jobs", {
    description: "number of jobs to run concurrently",
    alias: "j",
    default: defaults.concurrentJobs,
})
    .number("jobs")
    .option("max-pool-size", {
    description: "maximum size of the PostgreSQL pool",
    alias: "m",
    default: 10,
})
    .number("max-pool-size")
    .option("poll-interval", {
    description: "how long to wait between polling for jobs in milliseconds (for jobs scheduled in the future/retries)",
    default: defaults.pollInterval,
})
    .number("poll-interval")
    .option("no-prepared-statements", {
    description: "set this flag if you want to disable prepared statements, e.g. for compatibility with pgBouncer",
    default: false,
})
    .boolean("no-prepared-statements")
    .option("config", {
    alias: "C",
    description: "The path to the config file",
    normalize: true,
})
    .string("config")
    .option("cleanup", {
    description: "Clean the database, then exit. Accepts a comma-separated list of cleanup tasks: GC_TASK_IDENTIFIERS, GC_JOB_QUEUES, DELETE_PERMAFAILED_JOBS",
})
    .string("cleanup")
    .strict(true).argv;
const integerOrUndefined = (n) => {
    return typeof n === "number" && isFinite(n) && Math.round(n) === n
        ? n
        : undefined;
};
function stripUndefined(t) {
    return Object.fromEntries(Object.entries(t).filter(([_, value]) => value !== undefined));
}
function argvToPreset(inArgv) {
    return {
        worker: stripUndefined({
            connectionString: inArgv["connection"],
            maxPoolSize: integerOrUndefined(inArgv["max-pool-size"]),
            pollInterval: integerOrUndefined(inArgv["poll-interval"]),
            preparedStatements: !inArgv["no-prepared-statements"],
            schema: inArgv.schema,
            crontabFile: inArgv["crontab"],
            concurrentJobs: integerOrUndefined(inArgv.jobs),
        }),
    };
}
async function main() {
    const userPreset = await (0, load_1.loadConfig)(argv.config);
    const ONCE = argv.once;
    const SCHEMA_ONLY = argv["schema-only"];
    const CLEANUP = argv.cleanup;
    if (SCHEMA_ONLY && ONCE) {
        throw new Error("Cannot specify both --once and --schema-only");
    }
    const [compiledOptions, release] = await (0, lib_1.getUtilsAndReleasersFromOptions)({
        preset: {
            extends: [userPreset ?? preset_1.EMPTY_PRESET, argvToPreset(argv)],
        },
    });
    try {
        if (!compiledOptions.resolvedPreset.worker.connectionString &&
            !process.env.PGDATABASE) {
            throw new Error("Please use `--connection` flag, set `DATABASE_URL` or `PGDATABASE` envvars to indicate the PostgreSQL connection to use.");
        }
        if (SCHEMA_ONLY) {
            console.log("Schema updated");
            return;
        }
        const watchedTasks = await (0, getTasks_1.getTasksInternal)(compiledOptions, compiledOptions.resolvedPreset.worker.taskDirectory);
        compiledOptions.releasers.push(() => watchedTasks.release());
        if (CLEANUP != null) {
            const cleanups = Array.isArray(CLEANUP) ? CLEANUP : [CLEANUP];
            const cleanupTasks = cleanups
                .flatMap((t) => t.split(","))
                .map((t) => t.trim());
            (0, cleanup_1.assertCleanupTasks)(cleanupTasks);
            await (0, cleanup_1.cleanup)(compiledOptions, {
                tasks: cleanupTasks,
                taskIdentifiersToKeep: Object.keys(watchedTasks.tasks),
            });
            return;
        }
        const watchedCronItems = await (0, getCronItems_1.getCronItemsInternal)(compiledOptions, compiledOptions.resolvedPreset.worker.crontabFile);
        compiledOptions.releasers.push(() => watchedCronItems.release());
        if (ONCE) {
            await (0, runner_1.runOnceInternal)(compiledOptions, watchedTasks.tasks, () => {
                /* noop */
            });
        }
        else {
            const { promise } = await (0, runner_1.runInternal)(compiledOptions, watchedTasks.tasks, watchedCronItems.items, () => {
                /*noop*/
            });
            // Continue forever(ish)
            await promise;
        }
    }
    finally {
        const timer = setTimeout(() => {
            console.error(`Worker failed to exit naturally after 1 second; terminating manually. This may indicate a bug in Graphile Worker, or it might be that you triggered a forceful shutdown and some of your executing tasks have yet to exit.`);
            process.exit(1);
        }, 1000);
        timer.unref();
        compiledOptions.logger.debug("CLI shutting down...");
        await release();
        compiledOptions.logger.debug("CLI shutdown complete.");
    }
}
main().catch((e) => {
    console.error(e); // eslint-disable-line no-console
    process.exit(1);
});
//# sourceMappingURL=cli.js.map