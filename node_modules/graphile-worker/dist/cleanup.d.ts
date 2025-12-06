import { CleanupOptions, CleanupTask } from "./interfaces";
import { CompiledOptions } from "./lib";
export declare function assertCleanupTasks(tasks: string[]): asserts tasks is CleanupTask[];
export declare function cleanup(compiledOptions: CompiledOptions, options: CleanupOptions): Promise<void>;
