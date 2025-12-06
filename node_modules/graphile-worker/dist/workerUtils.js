"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.quickAddJob = exports.makeWorkerUtils = void 0;
/* eslint-disable @typescript-eslint/ban-types */
const cleanup_1 = require("./cleanup");
const lib_1 = require("./lib");
const migrate_1 = require("./migrate");
/**
 * Construct (asynchronously) a new WorkerUtils instance.
 */
async function makeWorkerUtils(options) {
    const [compiledOptions, release] = await (0, lib_1.getUtilsAndReleasersFromOptions)(options, {
        scope: {
            label: "WorkerUtils",
        },
    });
    const { logger, escapedWorkerSchema, withPgClient, addJob } = compiledOptions;
    return {
        withPgClient,
        logger,
        release,
        addJob,
        migrate: () => withPgClient((pgClient) => (0, migrate_1.migrate)(compiledOptions, pgClient)),
        async completeJobs(ids) {
            const { rows } = await withPgClient((client) => client.query(`select * from ${escapedWorkerSchema}.complete_jobs($1::bigint[])`, [ids]));
            return rows;
        },
        async permanentlyFailJobs(ids, reason) {
            const { rows } = await withPgClient((client) => client.query(`select * from ${escapedWorkerSchema}.permanently_fail_jobs($1::bigint[], $2::text)`, [ids, reason || null]));
            return rows;
        },
        async rescheduleJobs(ids, options) {
            const { rows } = await withPgClient((client) => client.query(`select * from ${escapedWorkerSchema}.reschedule_jobs(
            $1::bigint[],
            run_at := $2::timestamptz,
            priority := $3::int,
            attempts := $4::int,
            max_attempts := $5::int
          )`, [
                ids,
                options.runAt || null,
                options.priority || null,
                options.attempts || null,
                options.maxAttempts || null,
            ]));
            return rows;
        },
        async forceUnlockWorkers(workerIds) {
            await withPgClient((client) => client.query(`select ${escapedWorkerSchema}.force_unlock_workers($1::text[]);`, [workerIds]));
        },
        async cleanup(options = {
            tasks: ["GC_JOB_QUEUES"],
        }) {
            // TODO: would be great to guess the current task identifiers (e.g. by
            // reading the `tasks` folder) and add them to `taskIdentifiersToKeep`
            return (0, cleanup_1.cleanup)(compiledOptions, options);
        },
    };
}
exports.makeWorkerUtils = makeWorkerUtils;
/**
 * This function can be used to quickly add a job; however if you need to call
 * this more than once in your process you should instead create a WorkerUtils
 * instance for efficiency and performance sake.
 */
async function quickAddJob(options, identifier, payload, spec = {}) {
    const utils = await makeWorkerUtils(options);
    try {
        return await utils.addJob(identifier, payload, spec);
    }
    finally {
        await utils.release();
    }
}
exports.quickAddJob = quickAddJob;
//# sourceMappingURL=workerUtils.js.map