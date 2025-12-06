"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runInternal = exports.run = exports.runOnceInternal = exports.runOnce = exports.runMigrations = void 0;
const cron_1 = require("./cron");
const getTasks_1 = require("./getTasks");
const lib_1 = require("./lib");
const main_1 = require("./main");
const runMigrations = async (options) => {
    const [, release] = await (0, lib_1.getUtilsAndReleasersFromOptions)(options);
    await release();
};
exports.runMigrations = runMigrations;
/** @internal */
async function assertTaskList(compiledOptions, releasers) {
    const { resolvedPreset: { worker: { taskDirectory }, }, _rawOptions: { taskList }, } = compiledOptions;
    if (taskList) {
        return taskList;
    }
    else if (taskDirectory) {
        const watchedTasks = await (0, getTasks_1.getTasksInternal)(compiledOptions, taskDirectory);
        releasers.push(() => watchedTasks.release());
        return watchedTasks.tasks;
    }
    else {
        throw new Error("You must specify either `taskList` or `taskDirectory`");
    }
}
const runOnce = async (options, overrideTaskList) => {
    const [compiledOptions, release] = await (0, lib_1.getUtilsAndReleasersFromOptions)(options);
    return (0, exports.runOnceInternal)(compiledOptions, overrideTaskList, release);
};
exports.runOnce = runOnce;
const runOnceInternal = async (compiledOptions, overrideTaskList, release) => {
    const { withPgClient, releasers, resolvedPreset: { worker: { concurrentJobs: concurrency }, }, _rawOptions: { noHandleSignals }, } = compiledOptions;
    try {
        const taskList = overrideTaskList || (await assertTaskList(compiledOptions, releasers));
        const workerPool = (0, main_1._runTaskList)(compiledOptions, taskList, withPgClient, {
            concurrency,
            noHandleSignals,
            continuous: false,
        });
        return await workerPool.promise;
    }
    finally {
        await release();
    }
};
exports.runOnceInternal = runOnceInternal;
const run = async (rawOptions, overrideTaskList, overrideParsedCronItems) => {
    const [compiledOptions, release] = await (0, lib_1.getUtilsAndReleasersFromOptions)(rawOptions);
    return (0, exports.runInternal)(compiledOptions, overrideTaskList, overrideParsedCronItems, release);
};
exports.run = run;
const runInternal = async (compiledOptions, overrideTaskList, overrideParsedCronItems, release) => {
    const { releasers } = compiledOptions;
    try {
        const taskList = overrideTaskList || (await assertTaskList(compiledOptions, releasers));
        const parsedCronItems = overrideParsedCronItems ||
            (await (0, cron_1.getParsedCronItemsFromOptions)(compiledOptions, releasers));
        // The result of 'buildRunner' must be returned immediately, so that the
        // user can await its promise property immediately. If this is broken then
        // unhandled promise rejections could occur in some circumstances, causing
        // a process crash in Node v16+.
        return buildRunner({
            compiledOptions,
            taskList,
            parsedCronItems,
            release,
        });
    }
    catch (e) {
        try {
            await release();
        }
        catch (e2) {
            compiledOptions.logger.error(`Error occurred whilst attempting to release options after error occurred`, { error: e, secondError: e2 });
        }
        throw e;
    }
};
exports.runInternal = runInternal;
/**
 * This _synchronous_ function exists to ensure that the promises are built and
 * returned synchronously, such that an unhandled promise rejection error does
 * not have time to occur.
 *
 * @internal
 */
function buildRunner(input) {
    const { compiledOptions, taskList, parsedCronItems, release } = input;
    const { events, pgPool, releasers, addJob, logger } = compiledOptions;
    const cron = (0, cron_1.runCron)(compiledOptions, parsedCronItems, { pgPool, events });
    releasers.push(() => cron.release());
    const workerPool = (0, main_1.runTaskListInternal)(compiledOptions, taskList, pgPool);
    releasers.push(() => {
        if (!workerPool._shuttingDown) {
            return workerPool.gracefulShutdown("Runner is shutting down");
        }
    });
    let running = true;
    const stop = async () => {
        compiledOptions.logger.debug("Runner stopping");
        if (running) {
            running = false;
            events.emit("stop", {});
            try {
                const promises = [];
                if (cron._active) {
                    promises.push(cron.release());
                }
                if (workerPool._active) {
                    promises.push(workerPool.gracefulShutdown());
                }
                await Promise.all(promises).then(release);
            }
            catch (error) {
                logger.error(`Error occurred whilst attempting to release runner options: ${error.message}`, { error });
            }
        }
        else {
            throw new Error("Runner is already stopped");
        }
    };
    workerPool.promise.finally(() => {
        if (running) {
            stop();
        }
    });
    cron.promise.finally(() => {
        if (running) {
            stop();
        }
    });
    const promise = Promise.all([cron.promise, workerPool.promise]).then(() => {
        /* noop */
    }, async (error) => {
        if (running) {
            logger.error(`Stopping worker due to an error: ${error}`, { error });
            await stop();
        }
        else {
            logger.error(`Error occurred, but worker is already stopping: ${error}`, { error });
        }
        return Promise.reject(error);
    });
    return {
        stop,
        addJob,
        promise,
        events,
    };
}
//# sourceMappingURL=runner.js.map