"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.completeJob = void 0;
async function completeJob(compiledSharedOptions, withPgClient, workerId, job) {
    const { escapedWorkerSchema, workerSchema, resolvedPreset: { worker: { preparedStatements }, }, } = compiledSharedOptions;
    // TODO: retry logic, in case of server connection interruption
    if (job.job_queue_id != null) {
        await withPgClient.withRetries((client) => client.query({
            text: `\
with j as (
delete from ${escapedWorkerSchema}._private_jobs as jobs
where id = $1::bigint
returning *
)
update ${escapedWorkerSchema}._private_job_queues as job_queues
set locked_by = null, locked_at = null
from j
where job_queues.id = j.job_queue_id and job_queues.locked_by = $2::text;`,
            values: [job.id, workerId],
            name: !preparedStatements
                ? undefined
                : `complete_job_q/${workerSchema}`,
        }));
    }
    else {
        await withPgClient.withRetries((client) => client.query({
            text: `\
delete from ${escapedWorkerSchema}._private_jobs as jobs
where id = $1::bigint`,
            values: [job.id],
            name: !preparedStatements ? undefined : `complete_job/${workerSchema}`,
        }));
    }
}
exports.completeJob = completeJob;
//# sourceMappingURL=completeJob.js.map