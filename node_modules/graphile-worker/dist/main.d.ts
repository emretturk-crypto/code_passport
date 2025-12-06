import { Pool, PoolClient } from "pg";
import { EnhancedWithPgClient, RunOnceOptions, TaskList, WorkerPool, WorkerPoolOptions } from "./interfaces";
import { CompiledSharedOptions } from "./lib";
declare const allWorkerPools: Array<WorkerPool>;
export { allWorkerPools as _allWorkerPools };
export declare function runTaskList(rawOptions: WorkerPoolOptions, tasks: TaskList, pgPool: Pool): WorkerPool;
export declare function runTaskListInternal(compiledSharedOptions: CompiledSharedOptions<WorkerPoolOptions>, tasks: TaskList, pgPool: Pool): WorkerPool;
export declare function _runTaskList(compiledSharedOptions: CompiledSharedOptions<RunOnceOptions | WorkerPoolOptions>, tasks: TaskList, withPgClient: EnhancedWithPgClient, options: {
    concurrency?: number | undefined;
    noHandleSignals?: boolean | undefined;
    continuous: boolean;
    /** If false, you need to call `pool._start()` to start execution */
    autostart?: boolean;
    onDeactivate?: () => Promise<void> | void;
    onTerminate?: () => Promise<void> | void;
}): WorkerPool;
export declare const runTaskListOnce: (options: RunOnceOptions, tasks: TaskList, client: PoolClient) => WorkerPool;
