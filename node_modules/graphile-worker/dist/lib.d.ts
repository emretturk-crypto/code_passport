import { AsyncHooks } from "graphile-config";
import { Pool } from "pg";
import { makeWorkerPresetWorkerOptions } from "./config";
import { AddJobFunction, EnhancedWithPgClient, PromiseOrDirect, RunnerOptions, RunOnceOptions, SharedOptions, WithPgClient, WorkerEvents, WorkerOptions, WorkerSharedOptions, WorkerUtilsOptions } from "./interfaces";
import { Logger, LogScope } from "./logger";
export declare const BREAKING_MIGRATIONS: number[];
export type ResolvedWorkerPreset = GraphileConfig.ResolvedPreset & {
    worker: GraphileConfig.WorkerOptions & ReturnType<typeof makeWorkerPresetWorkerOptions>;
};
export interface CompiledSharedOptions<T extends SharedOptions = SharedOptions> {
    version: string;
    maxMigrationNumber: number;
    breakingMigrationNumbers: number[];
    events: WorkerEvents;
    logger: Logger;
    workerSchema: string;
    escapedWorkerSchema: string;
    /**
     * DO NOT USE THIS! As we move over to presets this will be removed.
     *
     * @internal
     */
    _rawOptions: T;
    resolvedPreset: ResolvedWorkerPreset;
    hooks: AsyncHooks<GraphileConfig.WorkerHooks>;
}
interface ProcessSharedOptionsSettings {
    scope?: LogScope;
}
export declare function processSharedOptions<T extends SharedOptions | WorkerSharedOptions | WorkerOptions | RunOnceOptions | WorkerUtilsOptions>(options: T, { scope }?: ProcessSharedOptionsSettings): CompiledSharedOptions<T>;
export type Releasers = Array<() => void | Promise<void>>;
export declare function assertPool(compiledSharedOptions: CompiledSharedOptions, releasers: Releasers): Promise<Pool>;
export type Release = () => PromiseOrDirect<void>;
export declare function withReleasers<T>(callback: (releasers: Releasers, release: Release) => Promise<T>): Promise<T>;
interface ProcessOptionsExtensions {
    pgPool: Pool;
    withPgClient: EnhancedWithPgClient;
    addJob: AddJobFunction;
    releasers: Releasers;
}
export interface CompiledOptions extends CompiledSharedOptions<RunnerOptions>, ProcessOptionsExtensions {
}
type CompiledOptionsAndRelease = [
    compiledOptions: CompiledOptions,
    release: (error?: Error) => PromiseOrDirect<void>
];
export declare const getUtilsAndReleasersFromOptions: (options: RunnerOptions, settings?: ProcessSharedOptionsSettings) => Promise<CompiledOptionsAndRelease>;
export declare function tryParseJson<T = object>(json: string | null | undefined): T | null;
export declare function makeEnhancedWithPgClient(withPgClient: WithPgClient | EnhancedWithPgClient): EnhancedWithPgClient;
export declare const sleep: (ms: number) => Promise<void>;
export {};
