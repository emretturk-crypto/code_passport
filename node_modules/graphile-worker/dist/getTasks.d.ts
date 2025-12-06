import { SharedOptions, WatchedTaskList } from "./interfaces";
import { CompiledSharedOptions } from "./lib";
export declare function getTasks(options: SharedOptions, taskPath: string): Promise<WatchedTaskList>;
export declare function getTasksInternal(compiledSharedOptions: CompiledSharedOptions, taskPath: string): Promise<WatchedTaskList>;
