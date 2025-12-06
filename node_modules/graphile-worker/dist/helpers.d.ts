import { Pool, PoolClient } from "pg";
import { AddJobFunction, EnhancedWithPgClient, Job, JobHelpers, WithPgClient } from "./interfaces";
import { CompiledSharedOptions } from "./lib";
import { Logger } from "./logger";
export declare function makeAddJob(compiledSharedOptions: CompiledSharedOptions, withPgClient: WithPgClient): AddJobFunction;
export declare function makeJobHelpers(compiledSharedOptions: CompiledSharedOptions, job: Job, { withPgClient, abortSignal, logger: overrideLogger, }: {
    withPgClient: EnhancedWithPgClient;
    abortSignal: AbortSignal | undefined;
    logger?: Logger;
}): JobHelpers;
export declare function makeWithPgClientFromPool(pgPool: Pool): <T>(callback: (pgClient: PoolClient) => Promise<T>) => Promise<T>;
export declare function makeWithPgClientFromClient(pgClient: PoolClient): <T>(callback: (pgClient: PoolClient) => Promise<T>) => Promise<T>;
