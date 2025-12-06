import { EnhancedWithPgClient } from "../interfaces";
import { CompiledSharedOptions } from "../lib";
export declare function getQueueNames(compiledSharedOptions: CompiledSharedOptions, withPgClient: EnhancedWithPgClient, queueIds: number[]): Promise<ReadonlyArray<string | null>>;
