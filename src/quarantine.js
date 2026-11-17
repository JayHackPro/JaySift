/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

import { promises as fs, existsSync } from "node:fs";
import path from "node:path";
import { sha256 } from "./hashes.js";
import { SERIOUS_FROM, SEVERITY_RANK, atLeast, topSeverity } from "./severity.js";

/**
 * Quarantine is how JaySift removes a threat without ever destroying data.
 * A flagged file is moved into a local vault and recorded in a manifest, so
 * the live site stops serving it immediately, yet every byte can be put back
 * with one command if a detection turns out to be wrong. Nothing is deleted
 * unless someone deliberately runs purge.
 *
 * A vault can end up inside a website, because by default it is made in the
 * folder the command is run from. So what it holds must never be something a
 * web server would run: a stored file is named <id>.quarantined with every
 * dot in the original name replaced, which leaves no .php or other script
 * ending for a server to act on, and the vault carries an .htaccess that
 * denies all access and empty index files that stop a folder listing.
 */

export const QUARANTINE_DIR = ".jaysift-quarantine";

/**
 * The vault name from before the tool was renamed. It is still read, so a
 * file quarantined under the old name can always be listed and restored.
 */
export const LEGACY_QUARANTINE_DIR = ".jayshield-quarantine";

/**
 * The vault to use when none is named. That is the current one, unless this
 * folder only holds a vault from before the rename, which then stays in use.
 */
export function defaultVaultDir() {
  if (!existsSync(QUARANTINE_DIR) && existsSync(LEGACY_QUARANTINE_DIR)) {
    return LEGACY_QUARANTINE_DIR;
  }
  return QUARANTINE_DIR;
}
const MANIFEST = "manifest.json";
const STORE = "files";
const STORED_SUFFIX = ".quarantined";

function sanitize(name) {
  return String(name).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80) || "file";
}

/**
 * The name a file is stored under. Apache can treat any dot-separated part of
 * a name as an extension, so shell.php.bak may still run as PHP. No dot from
 * the original name survives, and the one ending left means nothing to a server.
 */
export function storedName(id) {
  return String(id).replace(/\./g, "_") + STORED_SUFFIX;
}

const VAULT_FILES = {
  ".htaccess":
    "# JaySift quarantine vault. Nothing in this folder should ever be served.\n" +
    "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n" +
    "<IfModule !mod_authz_core.c>\n  Order allow,deny\n  Deny from all\n</IfModule>\n",
  "index.html": "",
  [STORE + "/index.html"]: "",
  "README.txt":
    "This folder is a JaySift quarantine vault.\n\n" +
    "It holds files that JaySift moved out of a site, renamed so that a web\n" +
    "server will not run them. manifest.json records where each one came from.\n\n" +
    "Keep this folder outside any folder a web server can reach.\n\n" +
    "  jaysift --list --vault <this folder>      show what is here\n" +
    "  jaysift --restore --vault <this folder>   put every file back\n"
};

/** Make the vault if it is not there, with the files that keep it from being served. */
async function ensureVault(vaultDir) {
  await fs.mkdir(path.join(vaultDir, STORE), { recursive: true });
  for (const [name, body] of Object.entries(VAULT_FILES)) {
    // Never overwrite: an owner may have edited these.
    await fs.writeFile(path.join(vaultDir, name), body, { flag: "wx" }).catch(() => {});
  }
}

/** Load the vault manifest, or an empty list if the vault is new. */
export async function loadManifest(vaultDir) {
  try {
    const raw = await fs.readFile(path.join(vaultDir, MANIFEST), "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data.entries) ? data : { version: 1, entries: [] };
  } catch {
    return { version: 1, entries: [] };
  }
}

async function saveManifest(vaultDir, manifest) {
  const file = path.join(vaultDir, MANIFEST);
  await fs.writeFile(file, JSON.stringify(manifest, null, 2) + "\n", "utf8");
}

/**
 * Move flagged files into the vault.
 *
 * Only files whose worst finding is high or critical are moved. A medium or
 * low finding is a reason to look at a file, not proof, so those files stay
 * where they are and come back in `skipped`. Pass `minSeverity` to move them
 * as well.
 *
 * @param {Array<{path:string,findings:Array}>} records  flagged records from a scan
 * @param {object} [options]
 * @param {string} [options.vaultDir]
 * @param {boolean} [options.dryRun]   report what would move without touching disk
 * @param {string} [options.minSeverity="high"]  the lowest severity to move
 * @returns {Promise<{vaultDir:string, created:boolean, minSeverity:string, moved:Array, skipped:Array, failed:Array, dryRun:boolean}>}
 *   `created` is true when this call made the vault.
 */
export async function quarantineFiles(records, options = {}) {
  const vaultDir = options.vaultDir || defaultVaultDir();
  const dryRun = Boolean(options.dryRun);
  const minSeverity = SEVERITY_RANK[options.minSeverity] ? options.minSeverity : SERIOUS_FROM;
  const moved = [];
  const skipped = [];
  const failed = [];

  // The vault is only made once there is something to put in it.
  const manifest = dryRun ? { version: 1, entries: [] } : await loadManifest(vaultDir);
  const vaultReal = path.resolve(vaultDir);
  const existed = existsSync(vaultDir);

  for (const record of records) {
    const abs = path.resolve(record.path);

    // Never quarantine the vault's own files.
    if (abs.startsWith(vaultReal + path.sep)) continue;

    const severity = topSeverity(record.findings);
    if (!atLeast(severity, minSeverity)) {
      skipped.push({ path: abs, severity });
      continue;
    }

    try {
      const stat = await fs.stat(abs);
      const id = sha256(abs).slice(0, 12) + "_" + sanitize(path.basename(abs));
      const storedRel = path.join(STORE, storedName(id));

      if (dryRun) {
        moved.push({ path: abs, id, dryRun: true });
        continue;
      }

      const storedAbs = path.join(vaultDir, storedRel);
      await ensureVault(vaultDir);
      // The same path quarantined again replaces its earlier copy, which is read-only.
      await fs.chmod(storedAbs, 0o600).catch(() => {});
      await fs.copyFile(abs, storedAbs);
      const digest = sha256(await fs.readFile(storedAbs));
      await fs.chmod(storedAbs, 0o400).catch(() => {});
      await fs.unlink(abs);

      const entry = {
        id,
        originalPath: abs,
        storedPath: storedRel,
        size: stat.size,
        sha256: digest,
        mode: stat.mode & 0o777,
        mtimeMs: stat.mtimeMs,
        quarantinedAt: new Date().toISOString(),
        reason: record.findings.map((f) => ({ id: f.id, name: f.name, severity: f.severity }))
      };
      manifest.entries = manifest.entries.filter((e) => e.originalPath !== abs);
      manifest.entries.push(entry);
      moved.push({ path: abs, id, quarantined: true });
    } catch (err) {
      failed.push({ path: abs, error: err.message });
    }
  }

  if (!dryRun && moved.length) await saveManifest(vaultDir, manifest);
  const created = !dryRun && !existed && existsSync(vaultDir);
  return { vaultDir, created, minSeverity, moved, skipped, failed, dryRun };
}

/**
 * Restore quarantined files back to where they came from.
 *
 * @param {object} [options]
 * @param {string} [options.vaultDir]
 * @param {string[]} [options.ids]   restore only these ids, or all if omitted
 * @param {boolean} [options.dryRun]
 */
export async function restoreFiles(options = {}) {
  const vaultDir = options.vaultDir || defaultVaultDir();
  const dryRun = Boolean(options.dryRun);
  const only = options.ids && options.ids.length ? new Set(options.ids) : null;
  const manifest = await loadManifest(vaultDir);

  const restored = [];
  const failed = [];
  const remaining = [];

  for (const entry of manifest.entries) {
    if (only && !only.has(entry.id)) {
      remaining.push(entry);
      continue;
    }
    if (dryRun) {
      restored.push({ path: entry.originalPath, id: entry.id, dryRun: true });
      remaining.push(entry);
      continue;
    }
    try {
      const storedAbs = path.join(vaultDir, entry.storedPath);
      await fs.mkdir(path.dirname(entry.originalPath), { recursive: true });
      await fs.copyFile(storedAbs, entry.originalPath);
      await fs.chmod(entry.originalPath, entry.mode || 0o644).catch(() => {});
      if (entry.mtimeMs) {
        const t = new Date(entry.mtimeMs);
        await fs.utimes(entry.originalPath, t, t).catch(() => {});
      }
      await fs.unlink(storedAbs).catch(() => {});
      restored.push({ path: entry.originalPath, id: entry.id });
    } catch (err) {
      failed.push({ path: entry.originalPath, id: entry.id, error: err.message });
      remaining.push(entry);
    }
  }

  if (!dryRun) {
    manifest.entries = remaining;
    await saveManifest(vaultDir, manifest);
  }
  return { vaultDir, restored, failed };
}

/** List everything currently held in the vault. */
export async function listQuarantine(options = {}) {
  const vaultDir = options.vaultDir || defaultVaultDir();
  const manifest = await loadManifest(vaultDir);
  return { vaultDir, entries: manifest.entries };
}

/**
 * Permanently delete quarantined files. This is the only destructive action
 * in JaySift, so it is never automatic and the CLI guards it behind an
 * explicit confirmation flag.
 */
export async function purgeQuarantine(options = {}) {
  const vaultDir = options.vaultDir || defaultVaultDir();
  const only = options.ids && options.ids.length ? new Set(options.ids) : null;
  const manifest = await loadManifest(vaultDir);
  const purged = [];
  const remaining = [];

  for (const entry of manifest.entries) {
    if (only && !only.has(entry.id)) {
      remaining.push(entry);
      continue;
    }
    await fs.unlink(path.join(vaultDir, entry.storedPath)).catch(() => {});
    purged.push({ path: entry.originalPath, id: entry.id });
  }

  manifest.entries = remaining;
  await saveManifest(vaultDir, manifest);
  return { vaultDir, purged };
}
