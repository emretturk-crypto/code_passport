import { LogFunctionFactory as GraphileLogFunctionFactory, Logger as GraphileLogger, LogLevel } from "@graphile/logger";
export interface LogScope {
    label?: string;
    workerId?: string;
    taskIdentifier?: string;
    jobId?: string;
}
export { LogLevel };
export declare class Logger extends GraphileLogger<LogScope> {
}
export type LogFunctionFactory = GraphileLogFunctionFactory<LogScope>;
export declare const consoleLogFactory: (scope: Partial<LogScope>) => (level: LogLevel, message: string) => void;
export declare const defaultLogger: Logger;
