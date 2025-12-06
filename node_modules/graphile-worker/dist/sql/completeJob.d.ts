import { DbJob, EnhancedWithPgClient } from "../interfaces";
import { CompiledSharedOptions } from "../lib";
export declare function completeJob(compiledSharedOptions: CompiledSharedOptions, withPgClient: EnhancedWithPgClient, workerId: string, job: DbJob): Promise<void>;
