"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoadTaskFromJsPlugin = void 0;
const url_1 = require("url");
const index_js_1 = require("../index.js");
const version_js_1 = require("../version.js");
const DEFAULT_EXTENSIONS = [".js", ".mjs", ".cjs"];
exports.LoadTaskFromJsPlugin = {
    name: "LoadTaskFromJsPlugin",
    version: version_js_1.version,
    worker: {
        hooks: {
            async loadTaskFromFiles(ctx, details) {
                // Check it hasn't already been handled
                if (details.handler) {
                    return;
                }
                const { resolvedPreset } = ctx;
                const { fileDetailsList } = details;
                let jsFile = undefined;
                const extensions = resolvedPreset?.worker?.fileExtensions ?? DEFAULT_EXTENSIONS;
                // Find a matching file in extension priority order
                outerloop: for (const extension of extensions) {
                    for (const fileDetails of fileDetailsList) {
                        if (fileDetails.extension === extension) {
                            jsFile = fileDetails;
                            break outerloop;
                        }
                    }
                }
                if (!jsFile) {
                    // Don't know how to handle; skip
                    return;
                }
                try {
                    const rawMod = await import((0, url_1.pathToFileURL)(jsFile.fullPath).href);
                    // Normally, import() of a commonJS module with `module.exports` write
                    // would result in `{ default: module.exports }`.
                    // TypeScript in CommonJS mode when imported with Node ESM can lead to
                    // two levels of `__esModule: true`; so we try and grab the inner one
                    // if we can.
                    const mod = rawMod.default?.default?.__esModule === true
                        ? rawMod.default.default
                        : rawMod.default?.__esModule === true
                            ? rawMod.default
                            : Object.keys(rawMod).length === 1 &&
                                typeof rawMod.default === "object" &&
                                rawMod.default !== null
                                ? rawMod.default
                                : rawMod;
                    // Always take the default export if there is one
                    const task = mod.default || mod;
                    if ((0, index_js_1.isValidTask)(task)) {
                        details.handler = task;
                    }
                    else {
                        throw new Error(`Invalid task '${jsFile.fullPath}' - expected function, received ${task ? typeof task : String(task)}.`);
                    }
                }
                catch (error) {
                    const message = `Error processing '${jsFile.fullPath}': ${error.message}`;
                    throw new Error(message);
                }
            },
        },
    },
};
//# sourceMappingURL=LoadTaskFromJsPlugin.js.map