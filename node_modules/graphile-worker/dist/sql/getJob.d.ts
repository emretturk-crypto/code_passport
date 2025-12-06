import { EnhancedWithPgClient, Job, TaskList } from "../interfaces";
import { CompiledSharedOptions } from "../lib";
export declare function isPromise<T>(t: T | Promise<T>): t is Promise<T>;
export declare function getJob(compiledSharedOptions: CompiledSharedOptions, withPgClient: EnhancedWithPgClient, tasks: TaskList, workerId: string, flagsToSkip: string[] | null): Promise<Job | undefined>;
