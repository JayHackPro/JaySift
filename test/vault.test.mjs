import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs, existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../src/scanner.js";
import { quarantineFiles, restoreFiles, listQuarantine, storedName } from "../src/quarantine.js";

const BIN = fileURLToPath(new URL("../bin/jaysift.js", import.meta.url));
const run = (args, opts = {}) =>
  spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" }, ...opts });

const SHELL = "<?php eval(base64_decode($_POST['x'])); // planted";

async function site(names = ["shell.php"]) {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "jaysift-vault-")));
  const root = path.join(dir, "site");
  await fs.mkdir(root);
  for (const name of names) await fs.writeFile(path.join(root, name), SHELL);
  return { dir, root, vault: path.join(dir, "vault") };
}

test("a stored file never carries a script ending", async () => {
  assert.equal(storedName("3f2a9c1b7d4e_shell.php"), "3f2a9c1b7d4e_shell_php.quarantined");
  const names = ["shell.php", "old.php.bak", "invoice.pdf.php", "x.phtml", "y.php5", "z.inc"];
  const { dir, root, vault } = await site(names);
  try {
    const q = await quarantineFiles((await scan([root])).flagged, { vaultDir: vault });
    assert.equal(q.moved.length, names.length);
    const stored = (await fs.readdir(path.join(vault, "files"))).filter((n) => n !== "index.html");
    assert.equal(stored.length, names.length);
    for (const name of stored) {
      assert.match(name, /^[0-9a-f]{12}_[A-Za-z0-9_-]+\.quarantined$/, name);
      assert.equal(name.split(".").length, 2, `only one dot, so no part of it reads as a script ending: ${name}`);
      assert.doesNotMatch(name, /\.(?:php\d?|phtml|pht|phar|inc|asp|aspx|pl|cgi)(?:\.|$)/i);
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("the vault denies web access and cannot be listed", async () => {
  const { dir, root, vault } = await site();
  try {
    const q = await quarantineFiles((await scan([root])).flagged, { vaultDir: vault });
    assert.equal(q.created, true);
    const htaccess = await fs.readFile(path.join(vault, ".htaccess"), "utf8");
    assert.match(htaccess, /Require all denied/);
    assert.match(htaccess, /Deny from all/);
    assert.equal(await fs.readFile(path.join(vault, "index.html"), "utf8"), "");
    assert.equal(await fs.readFile(path.join(vault, "files", "index.html"), "utf8"), "");
    assert.match(await fs.readFile(path.join(vault, "README.txt"), "utf8"), /outside any folder a web server can reach/);
    // JaySift's own vault files are not findings if the vault is ever scanned.
    const again = await scan([vault], { includeDirs: ["all"] });
    assert.deepEqual(
      again.flagged.map((r) => path.basename(r.path)).filter((n) => !n.endsWith(".quarantined")),
      []
    );
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("restore still returns every byte, mode and time, from the new store", async () => {
  const { dir, root, vault } = await site();
  try {
    const file = path.join(root, "shell.php");
    await fs.chmod(file, 0o640);
    const before = await fs.stat(file);
    const q = await quarantineFiles((await scan([root])).flagged, { vaultDir: vault });
    assert.equal(existsSync(file), false);
    const { entries } = await listQuarantine({ vaultDir: vault });
    assert.equal(entries[0].id, q.moved[0].id);
    assert.match(entries[0].id, /_shell\.php$/, "the id still shows the real name");
    assert.match(entries[0].storedPath, /\.quarantined$/);

    const r = await restoreFiles({ vaultDir: vault, ids: [entries[0].id] });
    assert.equal(r.restored.length, 1);
    assert.equal(await fs.readFile(file, "utf8"), SHELL);
    const after = await fs.stat(file);
    assert.equal(after.mode & 0o777, 0o640);
    assert.ok(Math.abs(after.mtimeMs - before.mtimeMs) < 2, "modified time kept to the millisecond");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("a file stored by an earlier version, under its own name, is still restored", async () => {
  const { dir, root, vault } = await site([]);
  try {
    const original = path.join(root, "old.php");
    await fs.mkdir(path.join(vault, "files"), { recursive: true });
    await fs.writeFile(path.join(vault, "files", "aaaaaaaaaaaa_old.php"), SHELL);
    await fs.writeFile(
      path.join(vault, "manifest.json"),
      JSON.stringify({ version: 1, entries: [{ id: "aaaaaaaaaaaa_old.php", originalPath: original, storedPath: path.join("files", "aaaaaaaaaaaa_old.php"), mode: 0o644, reason: [] }] })
    );
    const r = await restoreFiles({ vaultDir: vault });
    assert.equal(r.restored.length, 1);
    assert.equal(await fs.readFile(original, "utf8"), SHELL);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("the same path can be quarantined again after it comes back", async () => {
  const { dir, root, vault } = await site();
  try {
    const file = path.join(root, "shell.php");
    const first = await quarantineFiles((await scan([root])).flagged, { vaultDir: vault });
    assert.equal(first.created, true);
    await fs.writeFile(file, SHELL + " again");
    const second = await quarantineFiles((await scan([root])).flagged, { vaultDir: vault });
    assert.deepEqual(second.failed, []);
    assert.equal(second.moved.length, 1);
    assert.equal(second.created, false);
    assert.equal(existsSync(file), false);
    const r = await restoreFiles({ vaultDir: vault });
    assert.equal(r.restored.length, 1);
    assert.equal(await fs.readFile(file, "utf8"), SHELL + " again");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("the output says where the vault is, and warns when it is inside the scanned folder", async () => {
  const { dir, root } = await site();
  try {
    // Run from inside the site, the way it is done on a server: the vault lands in the site.
    const inside = run([".", "--quarantine", "--no-banner"], { cwd: root });
    const vault = path.join(root, ".jaysift-quarantine");
    assert.equal(inside.status, 1);
    assert.match(inside.stdout, /Created a quarantine vault and moved 1 file into it:/);
    assert.ok(inside.stdout.includes(vault), "the full path of the vault is printed");
    assert.match(inside.stdout, /This vault is inside the folder you scanned\./);
    assert.match(inside.stdout, /name a folder outside the site with --vault/);
    assert.ok(inside.stdout.includes(`jaysift --restore --vault ${vault}`));

    const json = JSON.parse(run([".", "--json", "--quarantine"], { cwd: root }).stdout);
    assert.equal(json.summary.flagged, 0, "the vault is skipped on the next scan");

    const list = run(["--list"], { cwd: root });
    assert.ok(list.stdout.includes(vault));

    // From another folder the vault is not found, and the tool says where it looked.
    const elsewhere = run(["--list"], { cwd: dir });
    assert.match(elsewhere.stdout, /There is no quarantine vault at /);
    assert.match(elsewhere.stdout, /name the vault with --vault <dir>/);
    const named = run(["--list", "--vault", vault], { cwd: dir });
    assert.match(named.stdout, /Quarantine vault \(1\)/);

    const back = run(["--restore", "--vault", vault], { cwd: dir });
    assert.match(back.stdout, /restored 1 file/);
    assert.equal(existsSync(path.join(root, "shell.php")), true);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("a vault outside the scanned folder gets no warning", async () => {
  const { dir, root, vault } = await site();
  try {
    const r = run([root, "--quarantine", "--vault", vault, "--no-banner"]);
    assert.ok(r.stdout.includes(vault));
    assert.doesNotMatch(r.stdout, /inside the folder you scanned/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
