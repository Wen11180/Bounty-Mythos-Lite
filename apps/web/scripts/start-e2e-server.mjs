import { spawn } from "node:child_process";

const port = process.env.PORT ?? "3100";
const hostname = process.env.HOSTNAME ?? "127.0.0.1";
const child = spawn(
  process.execPath,
  ["node_modules/next/dist/bin/next", "start", "--hostname", hostname, "--port", port],
  { env: process.env, stdio: "inherit" },
);

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => child.kill(signal));
}

child.once("exit", (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0);
});
