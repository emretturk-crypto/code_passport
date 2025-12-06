import { EnhancedWithPgClient } from "../interfaces";
import { CompiledSharedOptions } from "../lib";
export declare function resetLockedAt(compiledSharedOptions: CompiledSharedOptions, withPgClient: EnhancedWithPgClient): Promise<void>;
