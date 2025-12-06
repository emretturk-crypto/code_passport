import { PoolClient } from "pg";
import { migrations } from "./generated/sql";
import { WorkerSharedOptions } from "./interfaces";
import { CompiledSharedOptions } from "./lib";
/** @internal */
export declare function installSchema(compiledSharedOptions: CompiledSharedOptions<WorkerSharedOptions>, event: GraphileWorker.MigrateEvent): Promise<void>;
/** @internal */
export declare function runMigration(compiledSharedOptions: CompiledSharedOptions<WorkerSharedOptions>, event: GraphileWorker.MigrateEvent, migrationFile: keyof typeof migrations, migrationNumber: number): Promise<void>;
/** @internal */
export declare function migrate(compiledSharedOptions: CompiledSharedOptions<WorkerSharedOptions>, client: PoolClient): Promise<void>;
