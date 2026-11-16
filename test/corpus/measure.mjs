#!/usr/bin/env node
/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

/**
 * Count what the scanner catches, misses and wrongly flags on the corpus.
 *
 *   node test/corpus/measure.mjs                 measure this checkout
 *   node test/corpus/measure.mjs --src <dir>     measure another checkout's src folder
 *   node test/corpus/measure.mjs --json          print the per-file detail as JSON
 *   node test/corpus/measure.mjs --keep          leave the corpus on disk and print where
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildCorpus, measure } from "./corpus.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const value = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : null);

const src = path.resolve(value("--src") || path.join(here, "..", "..", "src"));
const { scan } = await import(pathToFileURL(path.join(src, "scanner.js")).href);

const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jaysift-corpus-"));
try {
  const { root, manifest } = await buildCorpus(dir);
  const byDefault = await measure(root, scan);
  const everything = await measure(root, scan, { includeDirs: ["all"], maxBytes: 10 * 1024 * 1024 });

  if (flag("--json")) {
    process.stdout.write(JSON.stringify({ src, default: byDefault, everything }, null, 2) + "\n");
  } else {
    const line = (label, g) =>
      `  ${label.padEnd(34)} ${String(g.flagged).padStart(2)} of ${g.total} flagged, ${String(g.serious).padStart(2)} as high or critical`;
    process.stdout.write(`\n  scanner: ${src}\n\n`);
    for (const group of ["textbook", "disguised", "clean"]) {
      process.stdout.write(line(`${group}, default settings`, byDefault.groups[group]) + "\n");
    }
    process.stdout.write(line("disguised, everything included", everything.groups.disguised) + "\n\n");

    const show = (title, rows) => {
      if (!rows.length) return;
      process.stdout.write(`  ${title}\n`);
      for (const f of rows) process.stdout.write(`    ${(f.top || "-").padEnd(9)} ${f.path}  (${f.technique})\n`);
      process.stdout.write("\n");
    };
    show("Bad files not flagged, default settings:", byDefault.files.filter((f) => f.group !== "clean" && !f.top));
    show("Bad files not flagged, everything included:", everything.files.filter((f) => f.group !== "clean" && !f.top));
    show("Clean files flagged:", byDefault.files.filter((f) => f.group === "clean" && f.top));
  }
  if (flag("--keep")) process.stdout.write(`  corpus kept at ${root}\n  manifest at ${manifest}\n\n`);
} finally {
  if (!flag("--keep")) await fs.rm(dir, { recursive: true, force: true });
}
