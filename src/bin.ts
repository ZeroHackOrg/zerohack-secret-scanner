#!/usr/bin/env node
/** zh-secret — scan files and trees for leaked secrets (keys, tokens, JWTs,
 *  private keys) using deterministic regex + entropy checks. */

import { Command } from "commander";
import { maskSecret } from "@zerohack/shared";
import { scanFile, scanTree } from "./scan.ts";
import type { SecretMatch } from "./scan.ts";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function maskLine(m: SecretMatch): string {
  return `${m.file}:${m.line}:${m.column}:${m.kind}:${maskSecret(m.matched)}`;
}

const program = new Command();
program
  .name("zh-secret")
  .description("Offline secret scanner: AWS keys, Google/GitHub/Slack/Stripe tokens, JWTs and PEM/OpenSSH private keys.")
  .version("0.1.0", "-v, --version")
  .showHelpAfterError();

program
  .command("scan <path>")
  .description("Scan a file or directory tree for secrets. Exit code 1 when matches are found.")
  .option("-i, --ignore <dirs...>", "extra names to ignore (in addition to .git, node_modules, etc.)")
  .option("-j, --json", "emit raw JSON")
  .action(async (path: string, opts: { ignore?: string[]; json?: boolean }) => {
    try {
      const isDir = (await import("node:fs")).statSync(path).isDirectory();
      const matches: SecretMatch[] = isDir
        ? await scanTree(path, { ignore: opts.ignore ?? [] })
        : await scanFile(path);

      if (opts.json) {
        console.log(JSON.stringify(matches, null, 2));
      } else {
        for (const m of matches) console.log(maskLine(m));
        if (isDir) {
          console.log(`Scanned ${path} — ${matches.length} secret(s) found.`);
        } else if (matches.length > 0) {
          console.log(`${matches.length} secret(s) found in ${path}.`);
        } else {
          console.log(`No secrets found in ${path}.`);
        }
      }
      if (matches.length > 0) process.exitCode = 1;
    } catch (err) {
      console.error(`zh-secret: ${errorMessage(err)}`);
      process.exit(1);
    }
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(`zh-secret: ${errorMessage(err)}`);
  process.exit(1);
});