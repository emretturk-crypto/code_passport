"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getCronItemsInternal = exports.getCronItems = void 0;
const fs_1 = require("fs");
const crontab_1 = require("./crontab");
const lib_1 = require("./lib");
async function loadCrontabIntoCronItems(logger, items, filename) {
    let didntExist = false;
    const contents = await fs_1.promises
        .readFile(filename, "utf8")
        .then((t) => {
        if (didntExist) {
            didntExist = false;
            logger.info(`Found crontab file '${filename}'; cron is now enabled`);
        }
        return t;
    })
        .catch((e) => {
        if (e.code !== "ENOENT") {
            // Only log error if it's not a "file doesn't exist" error
            logger.error(`Failed to read crontab file '${filename}': ${e}`);
        }
        else {
            didntExist = true;
            logger.info(`Failed to read crontab file '${filename}'; cron is disabled`);
        }
        return "";
    });
    if (contents != null) {
        const parsed = (0, crontab_1.parseCrontab)(contents);
        // Overwrite items' contents with the new cron items
        items.splice(0, items.length, ...parsed);
    }
}
async function getCronItems(options, crontabPath) {
    const compiledSharedOptions = (0, lib_1.processSharedOptions)(options);
    return getCronItemsInternal(compiledSharedOptions, crontabPath);
}
exports.getCronItems = getCronItems;
async function getCronItemsInternal(compiledSharedOptions, crontabPath) {
    const { logger } = compiledSharedOptions;
    const items = [];
    // Try and require it
    await loadCrontabIntoCronItems(logger, items, crontabPath);
    let released = false;
    return {
        items,
        release: () => {
            if (released) {
                return;
            }
            released = true;
        },
    };
}
exports.getCronItemsInternal = getCronItemsInternal;
//# sourceMappingURL=getCronItems.js.map