"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeWithPgClientFromClient = exports.makeWithPgClientFromPool = exports.makeJobHelpers = exports.makeAddJob = void 0;
const tslib_1 = require("tslib");
const deferred_1 = tslib_1.__importDefault(require("./deferred"));
const getQueueNames_1 = require("./sql/getQueueNames");
function makeAddJob(compiledSharedOptions, withPgClient) {
    const { escapedWorkerSchema, resolvedPreset: { worker: { useNodeTime }, }, } = compiledSharedOptions;
    return (identifier, payload, spec = {}) => {
        return withPgClient(async (pgClient) => {
            const { rows } = await pgClient.query(`
        select * from ${escapedWorkerSchema}.add_job(
          identifier => $1::text,
          payload => $2::json,
          queue_name => $3::text,
          run_at => $4::timestamptz,
          max_attempts => $5::int,
          job_key => $6::text,
          priority => $7::int,
          flags => $8::text[],
          job_key_mode => $9::text
        );
        `, [
                identifier,
                JSON.stringify(payload ?? {}),
                spec.queueName || null,
                // If there's an explicit run at, use that. Otherwise, if we've been
                // told to use Node time, use the current timestamp. Otherwise we'll
                // pass null and the function will use `now()` internally.
                spec.runAt
                    ? spec.runAt.toISOString()
                    : useNodeTime
                        ? new Date().toISOString()
                        : null,
                spec.maxAttempts || null,
                spec.jobKey || null,
                spec.priority || null,
                spec.flags || null,
                spec.jobKeyMode || null,
            ]);
            const job = rows[0];
            job.task_identifier = identifier;
            return job;
        });
    };
}
exports.makeAddJob = makeAddJob;
const $$cache = Symbol("queueNameById");
const $$nextBatch = Symbol("pendingQueueIds");
function getQueueName(compiledSharedOptions, withPgClient, queueId) {
    if (queueId == null) {
        return null;
    }
    let rawCache = compiledSharedOptions[$$cache];
    if (!rawCache) {
        rawCache = compiledSharedOptions[$$cache] = Object.create(null);
    }
    // Appease TypeScript; this is not null
    const cache = rawCache;
    const existing = cache[queueId];
    if (existing !== undefined) {
        return existing;
    }
    let nextBatch = compiledSharedOptions[$$nextBatch];
    // Not currently requested; queue us (and don't queue us again)
    const promise = (0, deferred_1.default)();
    cache[queueId] = promise;
    if (nextBatch) {
        // Already scheduled; add us to the next batch
        nextBatch.push(queueId);
    }
    else {
        // Need to create the batch
        nextBatch = compiledSharedOptions[$$nextBatch] = [];
        nextBatch.push(queueId);
        // Appease TypeScript; this is not null
        const queueIds = nextBatch;
        // Schedule the batch to run
        setTimeout(() => {
            // Allow another batch to start processing
            compiledSharedOptions[$$nextBatch] = undefined;
            // Get this batches names
            (0, getQueueNames_1.getQueueNames)(compiledSharedOptions, withPgClient, queueIds)
                .then((names) => {
                //assert.equal(queueIds.length, names.length);
                for (let i = 0, l = queueIds.length; i < l; i++) {
                    const queueId = queueIds[i];
                    const name = names[i];
                    const cached = cache[queueId];
                    if (typeof cached === "object") {
                        // It's a deferred; need to resolve/reject
                        if (name != null) {
                            cached.resolve(name);
                            cache[queueId] = name;
                        }
                        else {
                            cached.reject(new Error(`Queue with id '${queueId}' not found`));
                            // Try again
                            cache[queueId] = undefined;
                        }
                    }
                    else {
                        // It's already cached... but we got it again?!
                        if (name != null) {
                            cache[queueId] = name;
                        }
                        else {
                            // Try again
                            cache[queueId] = undefined;
                        }
                    }
                }
            }, (e) => {
                // An error occurred; reject all the deferreds but allow them to run again
                for (const queueId of queueIds) {
                    cache[queueId].reject(e);
                    // Retry next time
                    cache[queueId] = undefined;
                }
            })
                .catch((e) => {
                // This should never happen
                console.error(`Graphile Worker Internal Error`, e);
            });
        }, compiledSharedOptions.resolvedPreset.worker.getQueueNameBatchDelay ?? 50);
    }
    return promise;
}
function makeJobHelpers(compiledSharedOptions, job, { withPgClient, abortSignal, logger: overrideLogger, }) {
    const baseLogger = overrideLogger ?? compiledSharedOptions.logger;
    const logger = baseLogger.scope({
        label: "job",
        taskIdentifier: job.task_identifier,
        jobId: job.id,
    });
    const helpers = {
        abortSignal,
        job,
        getQueueName(queueId = job.job_queue_id) {
            return getQueueName(compiledSharedOptions, withPgClient, queueId);
        },
        logger,
        withPgClient,
        query: (queryText, values) => withPgClient((pgClient) => pgClient.query(queryText, values)),
        addJob: makeAddJob(compiledSharedOptions, withPgClient),
        // TODO: add an API for giving workers more helpers
    };
    // DEPRECATED METHODS
    Object.assign(helpers, {
        debug(format, ...parameters) {
            logger.error("REMOVED: `helpers.debug` has been replaced with `helpers.logger.debug`; please do not use `helpers.debug`");
            logger.debug(format, { parameters });
        },
    });
    return helpers;
}
exports.makeJobHelpers = makeJobHelpers;
function makeWithPgClientFromPool(pgPool) {
    return async function withPgClientFromPool(callback) {
        const client = await pgPool.connect();
        try {
            return await callback(client);
        }
        finally {
            await client.release();
        }
    };
}
exports.makeWithPgClientFromPool = makeWithPgClientFromPool;
function makeWithPgClientFromClient(pgClient) {
    return async (callback) => {
        return callback(pgClient);
    };
}
exports.makeWithPgClientFromClient = makeWithPgClientFromClient;
//# sourceMappingURL=helpers.js.map