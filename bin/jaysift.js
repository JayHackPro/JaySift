#!/usr/bin/env node
/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

import { promises as fs, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../src/scanner.js";
import { DEFAULT_SKIP_DIRS } from "../src/walk.js";
import { parseHashList } from "../src/hashes.js";
import {
  quarantineFiles,
  restoreFiles,
  listQuarantine,
  purgeQuarantine,
  QUARANTINE_DIR,
  defaultVaultDir
} from "../src/quarantine.js";
import { formatHuman, toJson, summaryLine } from "../src/report.js";
import { renderBanner } from "../src/banner.js";
import { selfTest } from "../src/selftest.js";
import { color, setColor, severityColor } from "../src/colors.js";

const SEVERITIES = ["critical", "high", "medium", "low"];
const here = path.dirname(fileURLToPath(import.meta.url));

/** The JayHackPro brand banner, with the JaySift subtitle. */
function brandBanner(v) {
  return renderBanner({
    subtitle: "JaySift  ·  find and remove web malware",
    version: v,
    url: "github.com/JayHackPro/JaySift"
  });
}

async function version() {
  try {
    const pkg = JSON.parse(await fs.readFile(path.join(here, "..", "package.json"), "utf8"));
    return pkg.version || "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const BOOLEAN_FLAGS = new Set([
  "quarantine", "restore", "list", "purge", "selftest",
  "json", "follow-symlinks", "no-color", "verbose", "dry-run",
  "yes", "help", "version", "banner", "no-banner"
]);
const VALUE_FLAGS = new Set(["min-severity", "quarantine-severity", "ignore-rule", "hashes", "max-size", "vault", "include"]);
const LIST_FLAGS = new Set(["ignore-rule", "include"]);
const ALIASES = { h: "help", V: "version", v: "verbose", q: "quarantine", j: "json" };

// A website address is not something JaySift can open. It reads files.
const LOOKS_LIKE_URL = /^[a-z][a-z0-9+.-]*:\/\//i;
const LOOKS_LIKE_HOST = /^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/.*)?$/i;
const GUIDE_URL = "https://github.com/JayHackPro/JaySift#scan-a-wordpress-site";

function parseArgs(argv) {
  const flags = { "ignore-rule": [], include: [] };
  const positionals = [];
  let bad = null;

  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i];
    if (arg === "--") {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (arg.startsWith("--")) {
      let name = arg.slice(2);
      let value = null;
      const eq = name.indexOf("=");
      if (eq !== -1) {
        value = name.slice(eq + 1);
        name = name.slice(0, eq);
      }
      if (VALUE_FLAGS.has(name)) {
        if (value === null) value = argv[++i];
        if (value === undefined) { bad = `--${name} needs a value`; break; }
        if (LIST_FLAGS.has(name)) flags[name].push(...value.split(",").map((s) => s.trim()).filter(Boolean));
        else flags[name] = value;
      } else if (BOOLEAN_FLAGS.has(name)) {
        flags[name] = true;
      } else {
        bad = `unknown option --${name}`;
        break;
      }
    } else if (arg.startsWith("-") && arg.length > 1) {
      const short = arg.slice(1);
      const full = ALIASES[short];
      if (!full) { bad = `unknown option -${short}`; break; }
      flags[full] = true;
    } else {
      positionals.push(arg);
    }
  }
  return { flags, positionals, bad };
}

function helpText(v) {
  return `
  ${color.bold("Find and remove web malware, webshells, and backdoors.")}

  ${color.bold("Usage")}
    jaysift [paths...] [options]

  ${color.bold("Scan")}   ${color.dim("(read-only, nothing is changed)")}
    jaysift ./public_html            scan a folder
    jaysift file.php app/            scan several targets
    jaysift .                        scan the current folder
    jaysift . --min-severity high    show only high and critical
    jaysift . --include vendor       also scan a folder skipped by name
    jaysift . --json > report.json   machine-readable output
    jaysift . --verbose              include rule ids and references

  ${color.bold("Websites")}
    JaySift reads files on disk. It does not connect to a URL.
    To check a live site, run it on the server over SSH, or on a copy of
    the site downloaded with SFTP or a backup. WordPress files that are
    flagged are marked, with advice to replace rather than only remove.
    ${color.dim(GUIDE_URL)}

  ${color.bold("Remove")}   ${color.dim("(safe: files are moved, never deleted)")}
    jaysift . --quarantine           move critical and high findings into a local vault
    jaysift . --quarantine --dry-run preview what would move
    jaysift . --quarantine --quarantine-severity low
                                     move medium and low findings too
    jaysift --list                   show what is in the vault
    jaysift --restore                put every quarantined file back
    jaysift --restore <id>           put one file back
    jaysift --purge --yes            permanently delete the vault (last resort)

  ${color.bold("Prove it works")}
    jaysift --selftest               detect the EICAR test file end to end

  ${color.bold("Options")}
    --min-severity <level>   critical | high | medium | low
    --quarantine-severity <level>
                             lowest severity --quarantine moves (default high)
    --ignore-rule <id,...>   silence one or more rules
    --include <dir,...>      scan folders skipped by name, or "all"
                             (skipped: ${[...DEFAULT_SKIP_DIRS].join(" ")})
    --hashes <file>          add known-bad sha256 hashes (one per line)
    --max-size <MB>          skip files larger than this (default 5)
    --vault <dir>            quarantine folder (default ${QUARANTINE_DIR} in the
                             folder you run from; keep it outside the website)
    --follow-symlinks        follow symbolic links (off by default)
    --dry-run                show actions without changing anything
    --json                   output JSON
    --no-color               plain text
    --no-banner              hide the startup banner
    --banner                 print the banner and exit
    -v, --verbose            more detail
    -V, --version            print version
    -h, --help               this help

  ${color.bold("Exit codes")}   ${color.dim("0 clean   1 something was flagged   2 error")}

  ${color.dim("JayHackPro® Inc.  Let's make the world a better place.")}
  ${color.dim("https://github.com/JayHackPro/JaySift")}
`;
}

function fail(message) {
  process.stderr.write(color.red("  error: ") + message + "\n");
  process.stderr.write(color.dim("  run  jaysift --help  for usage\n"));
  process.exitCode = 2;
}

/** Someone passed a website address. Say plainly what JaySift can do instead. */
function failUrl(target) {
  const host = target.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/\/.*$/, "") || "example.com";
  const lines = [
    `JaySift scans files on disk. It cannot connect to ${target}.`,
    "  To check that site, run JaySift where its files are:",
    color.brand(`    on the server, over SSH      jaysift /var/www/${host}/public_html`),
    color.brand(`    or on a downloaded copy      jaysift ~/Downloads/${host}`),
    "  Get the files with SFTP, your host's file manager, or a full site backup.",
    color.dim(`  Guide: ${GUIDE_URL}`)
  ];
  fail(lines.join("\n"));
}

async function main() {
  const { flags, positionals, bad } = parseArgs(process.argv.slice(2));
  if (flags["no-color"] || flags.json) setColor(false);

  const v = await version();
  if (flags.banner) { process.stdout.write(brandBanner(v) + "\n"); return; }
  if (flags.help) { process.stdout.write(brandBanner(v) + helpText(v) + "\n"); return; }
  if (flags.version) { process.stdout.write(v + "\n"); return; }
  if (bad) { fail(bad); return; }

  const vaultDir = flags.vault || defaultVaultDir();

  // ----- Vault management modes
  if (flags.selftest) return runSelfTest(flags, v);
  if (flags.list) return runList(vaultDir, flags);
  if (flags.restore) return runRestore(vaultDir, positionals, flags);
  if (flags.purge) return runPurge(vaultDir, positionals, flags);

  // ----- Scan mode
  if (flags["min-severity"] && !SEVERITIES.includes(flags["min-severity"])) {
    return fail(`--min-severity must be one of ${SEVERITIES.join(", ")}`);
  }
  if (flags["quarantine-severity"] && !SEVERITIES.includes(flags["quarantine-severity"])) {
    return fail(`--quarantine-severity must be one of ${SEVERITIES.join(", ")}`);
  }

  let extraHashes;
  if (flags.hashes) {
    try {
      extraHashes = parseHashList(await fs.readFile(flags.hashes, "utf8"));
    } catch (err) {
      return fail(`could not read hash list ${flags.hashes}: ${err.message}`);
    }
  }

  let maxBytes;
  if (flags["max-size"]) {
    const mb = Number(flags["max-size"]);
    if (!Number.isFinite(mb) || mb <= 0) return fail("--max-size must be a positive number of megabytes");
    maxBytes = Math.round(mb * 1024 * 1024);
  }

  const targets = positionals.length ? positionals : ["."];
  for (const t of targets) {
    if (LOOKS_LIKE_URL.test(t)) return failUrl(t);
    try {
      await fs.access(t);
    } catch {
      if (LOOKS_LIKE_HOST.test(t)) return failUrl(t);
      return fail(`no such file or folder: ${t}`);
    }
  }

  const result = await scan(targets, {
    ignoreRules: new Set(flags["ignore-rule"]),
    includeDirs: flags.include,
    extraHashes,
    maxBytes,
    minSeverity: flags["min-severity"],
    followSymlinks: Boolean(flags["follow-symlinks"])
  });

  const showBanner = !flags.json && !flags["no-banner"];

  // Quarantine moves critical and high findings. Medium and low are reasons
  // to look at a file, so they stay put unless --quarantine-severity says so.
  let quarantine = null;
  if (flags.quarantine && result.flagged.length) {
    quarantine = await quarantineFiles(result.flagged, {
      vaultDir,
      dryRun: Boolean(flags["dry-run"]),
      minSeverity: flags["quarantine-severity"]
    });
    if (flags["dry-run"] && !flags.json) {
      if (showBanner) process.stdout.write(brandBanner(v));
      process.stdout.write(formatHuman(result, { verbose: flags.verbose, header: !showBanner }));
      const left = quarantine.skipped.length
        ? ` and leave ${quarantine.skipped.length} file(s) with lesser findings in place`
        : "";
      process.stdout.write(
        "\n  " + color.yellow(color.bold("Dry run")) +
        color.dim(` would move ${quarantine.moved.length} file(s) into ${path.resolve(quarantine.vaultDir)}${left}. Nothing was changed.`) + "\n\n"
      );
      process.exitCode = 1;
      return;
    }
    if (quarantine.failed.length && !flags.json) {
      for (const f of quarantine.failed) process.stderr.write(color.red("  could not quarantine ") + f.path + ": " + f.error + "\n");
    }
  }

  if (flags.json) {
    process.stdout.write(toJson(result, { version: v, quarantine }) + "\n");
  } else {
    if (showBanner) process.stdout.write(brandBanner(v));
    process.stdout.write(formatHuman(result, { verbose: flags.verbose, quarantine, header: !showBanner }));
    process.stderr.write(color.dim("  " + summaryLine(result)) + "\n");
  }

  process.exitCode = result.flagged.length ? 1 : 0;
}

async function runSelfTest(flags, v) {
  const res = await selfTest();
  if (flags.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + "\n");
    process.exitCode = res.passed ? 0 : 1;
    return;
  }
  if (!flags["no-banner"]) process.stdout.write(brandBanner(v));
  process.stdout.write("  " + color.brand(color.bold("self-test")) + "\n\n");
  for (const c of res.checks) {
    const mark = c.ok ? color.green("✔") : color.red("✕");
    process.stdout.write(`  ${mark} ${c.name}\n     ${color.dim(c.detail)}\n`);
  }
  process.stdout.write("\n  " + (res.passed
    ? color.green(color.bold("All checks passed. JaySift is working."))
    : color.red(color.bold("Some checks failed."))) + "\n\n");
  process.exitCode = res.passed ? 0 : 1;
}

/**
 * Say where the vault was looked for. A vault is made in the folder the
 * quarantine was run from, so from anywhere else it has to be named.
 */
function noVaultNote(where, emptyWord) {
  return existsSync(where)
    ? `The quarantine vault at ${where} ${emptyWord}.`
    : `There is no quarantine vault at ${where}.\n  A vault is made in the folder --quarantine was run from. Run this from that folder, or name the vault with --vault <dir>.`;
}

async function runList(vaultDir, flags) {
  const { entries } = await listQuarantine({ vaultDir });
  if (flags.json) { process.stdout.write(JSON.stringify(entries, null, 2) + "\n"); return; }
  const where = path.resolve(vaultDir);
  if (!entries.length) {
    process.stdout.write("\n  " + color.dim(noVaultNote(where, "is empty")) + "\n\n");
    return;
  }
  process.stdout.write("\n  " + color.bold(`Quarantine vault (${entries.length})`) + color.dim(`  ${where}`) + "\n\n");
  for (const e of entries) {
    const worst = e.reason[0] ? severityColor(e.reason[0].severity)(e.reason[0].severity) : color.dim("unknown");
    process.stdout.write(`  ${color.dim(e.id)}  ${e.originalPath}\n     ${worst}  ${color.dim(e.quarantinedAt)}\n`);
  }
  process.stdout.write("\n  " + color.dim("Restore with  jaysift --restore <id>  or  --restore  for all.") + "\n\n");
}

async function runRestore(vaultDir, ids, flags) {
  const res = await restoreFiles({ vaultDir, ids, dryRun: Boolean(flags["dry-run"]) });
  if (flags.json) { process.stdout.write(JSON.stringify(res, null, 2) + "\n"); return; }
  if (!res.restored.length) {
    process.stdout.write("\n  " + color.dim("Nothing to restore. " + noVaultNote(path.resolve(vaultDir), "is empty")) + "\n\n");
    return;
  }
  const word = flags["dry-run"] ? "would restore" : "restored";
  process.stdout.write("\n  " + color.green(color.bold(`${word} ${res.restored.length} file(s)`)) + "\n");
  for (const r of res.restored) process.stdout.write("     " + r.path + "\n");
  for (const f of res.failed) process.stderr.write(color.red("     failed: ") + f.path + " " + f.error + "\n");
  process.stdout.write("\n");
}

async function runPurge(vaultDir, ids, flags) {
  if (!flags.yes) {
    return fail("purge permanently deletes quarantined files. Re-run with --yes to confirm.");
  }
  const res = await purgeQuarantine({ vaultDir, ids });
  if (flags.json) { process.stdout.write(JSON.stringify(res, null, 2) + "\n"); return; }
  process.stdout.write("\n  " + color.yellow(color.bold(`purged ${res.purged.length} file(s) permanently`)) + "\n\n");
}

main().catch((err) => {
  process.stderr.write(color.red("  JaySift error: ") + (err && err.stack ? err.stack : String(err)) + "\n");
  process.exitCode = 2;
});
