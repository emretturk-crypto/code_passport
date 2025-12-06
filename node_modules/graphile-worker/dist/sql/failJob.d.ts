import { DbJob, EnhancedWithPgClient } from "../interfaces";
import { CompiledSharedOptions } from "../lib";
export declare function failJob(compiledSharedOptions: CompiledSharedOptions, withPgClient: EnhancedWithPgClient, workerId: string, job: DbJob, message: string, replacementPayload: undefined | unknown[]): Promise<void>;
export declare function failJobs(compiledSharedOptions: CompiledSharedOptions, withPgClient: EnhancedWithPgClient, workerIds: string[], jobs: DbJob[], message: string): Promise<DbJob[]>;
