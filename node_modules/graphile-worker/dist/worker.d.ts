import { EnhancedWithPgClient, TaskList, Worker, WorkerPool, WorkerSharedOptions } from "./interfaces";
import { CompiledSharedOptions } from "./lib";
export declare function makeNewWorker(compiledSharedOptions: CompiledSharedOptions<WorkerSharedOptions>, params: {
    tasks: TaskList;
    withPgClient: EnhancedWithPgClient;
    continuous: boolean;
    abortSignal: AbortSignal;
    workerPool: WorkerPool;
    autostart?: boolean;
    workerId?: string;
}): Worker;
