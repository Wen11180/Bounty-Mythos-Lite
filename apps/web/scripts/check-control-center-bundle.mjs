import { readFile, stat } from "node:fs/promises";
import { dirname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const budgetBytes = 500 * 1024;
const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = join(
  webRoot,
  ".next",
  "server",
  "app",
  "page_client-reference-manifest.js",
);

const manifestSource = await readFile(manifestPath, "utf8").catch((error) => {
  throw new Error(`Control-center build manifest is missing: ${manifestPath}`, { cause: error });
});
const match = manifestSource.match(/__RSC_MANIFEST\["\/page"\] = (\{.*\});?\s*$/s);
if (!match) {
  throw new Error(`Unable to parse the control-center build manifest: ${manifestPath}`);
}
const manifest = JSON.parse(match[1]);
const entryFiles = manifest.entryJSFiles?.["[project]/app/page"];
if (!Array.isArray(entryFiles) || entryFiles.length === 0) {
  throw new Error("Control-center entry JS files are missing from the page manifest.");
}

const files = [...new Set(entryFiles)]
  .map((entry) => {
    if (typeof entry !== "string" || !entry.startsWith("static/")) {
      throw new Error(`Unexpected control-center entry path: ${String(entry)}`);
    }
    return entry;
  })
  .sort();
const measurements = await Promise.all(
  files.map(async (entry) => {
    const path = join(webRoot, ".next", ...entry.split("/"));
    const source = await readFile(path);
    return {
      bytes: (await stat(path)).size,
      entry,
      gzipBytes: gzipSync(source).length,
    };
  }),
);
const totalGzipBytes = measurements.reduce((total, item) => total + item.gzipBytes, 0);

console.log("Control-center initial JavaScript (gzip):");
for (const item of measurements) {
  console.log(
    `${normalize(item.entry)}: ${item.gzipBytes} gzip bytes (${item.bytes} raw bytes)`,
  );
}
console.log(`Total: ${totalGzipBytes} gzip bytes; budget: ${budgetBytes} bytes`);

if (totalGzipBytes > budgetBytes) {
  throw new Error(
    `Control-center initial JavaScript is ${totalGzipBytes} gzip bytes, exceeding ${budgetBytes} bytes.`,
  );
}
