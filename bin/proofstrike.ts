#!/usr/bin/env node
import { runCli } from "../packages/cli/src/index.js";

runCli(process.argv.slice(2)).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`proofstrike: ${message}`);
  process.exitCode = 1;
});
