import { SharedOptions, WatchedCronItems } from "./interfaces";
import { CompiledSharedOptions } from "./lib";
export declare function getCronItems(options: SharedOptions, crontabPath: string): Promise<WatchedCronItems>;
export declare function getCronItemsInternal(compiledSharedOptions: CompiledSharedOptions, crontabPath: string): Promise<WatchedCronItems>;
