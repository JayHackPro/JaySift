import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs, existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../src/scanner.js";
import { quarantineFiles, restoreFiles } from "../src/quarantine.js";
import { formatHuman, summaryLine, toJson } from "../src/report.js";
import { topSeverity, verdictFor, countVerdicts } from "../src/severity.js";
import { setColor } from "../src/colors.js";

const BIN = fileURLToPath(new URL("../bin/jaysift.js", import.meta.url));
const run = (args, opts = {}) =>
  spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" }, ...opts });

const CRITICAL = "<?php eval(base64_decode($_POST['x']));";
const HIGH = "<?php $f = create_function('', 'return 1;');";
const MEDIUM = '<nav><div style="display:none"><a href="/a">A</a> <a href="/b">B</a></div></nav>';
const LOW = "<?php move_uploaded_file($_FILES['f']['tmp_name'], $dest);";

/** A folder with one file at each severity, plus a clean one. */
async function tree(which = ["critical", "high", "medium", "low"]) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jaysift-verdict-"));
  const site = path.join(dir, "site");
  await fs.mkdir(site);
  const bodies = { critical: CRITICAL, high: HIGH, medium: MEDIUM, low: LOW };
  const files = {};
  for (const level of which) {
    files[level] = path.join(site, `${level}.php`);
    await fs.writeFile(files[level], bodies[level]);
  }
  await fs.writeFile(path.join(site, "clean.php"), "<?php echo 'hello';");
  return { dir, site, files, vault: path.join(dir, "vault") };
}

test("critical and high are likely malicious; medium and low are for review", () => {
  assert.equal(verdictFor("critical"), "likely-malicious");
  assert.equal(verdictFor("high"), "likely-malicious");
  assert.equal(verdictFor("medium"), "review");
  assert.equal(verdictFor("low"), "review");
  assert.equal(topSeverity([{ severity: "low" }, { severity: "high" }, { severity: "medium" }]), "high");
  assert.equal(topSeverity([]), null);
});

test("every flagged file carries its severity and verdict, and the old list name still works", async () => {
  const { dir, site } = await tree();
  try {
    const result = await scan([site]);
    assert.equal(result.flagged.length, 4);
    assert.equal(result.infected, result.flagged, "infected is the same list under its old name");
    const byName = Object.fromEntries(result.flagged.map((r) => [path.basename(r.path, ".php"), r]));
    for (const level of ["critical", "high", "medium", "low"]) assert.equal(byName[level].severity, level);
    assert.equal(byName.critical.verdict, "likely-malicious");
    assert.equal(byName.high.verdict, "likely-malicious");
    assert.equal(byName.medium.verdict, "review");
    assert.equal(byName.low.verdict, "review");
    assert.deepEqual(countVerdicts(result.flagged), { likelyMalicious: 2, review: 2 });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("the report does not call anything infected, and says which findings are only worth a look", async () => {
  const { dir, site } = await tree();
  setColor(false);
  try {
    const result = await scan([site]);
    const text = formatHuman(result);
    assert.doesNotMatch(text, /infected/i);
    assert.match(text, /2 likely malicious \(critical or high\), 2 worth a look \(medium or low\), 1 clean/);
    assert.match(text, /reason to look at a file, not proof/);
    assert.match(text, /move the 2 files marked critical or high/);
    assert.match(text, /leaves the 2 files marked medium or low where they are/);
    assert.equal(summaryLine(result), "critical risk: 2 likely malicious, 2 to review of 5 scanned");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("a scan with only medium and low findings says nothing is likely malware", async () => {
  const { dir, site } = await tree(["medium", "low"]);
  setColor(false);
  try {
    const result = await scan([site]);
    const text = formatHuman(result);
    assert.doesNotMatch(text, /infected/i);
    assert.match(text, /0 likely malicious/);
    assert.match(text, /Nothing here is likely to be malware/);
    assert.match(text, /--quarantine leaves them in place/);
    assert.equal(summaryLine(result), "to review: 2 files worth a look of 3 scanned, none likely malicious");
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("JSON carries the new names and keeps the old ones", async () => {
  const { dir, site } = await tree();
  try {
    const data = JSON.parse(toJson(await scan([site])));
    assert.equal(data.summary.flagged, 4);
    assert.equal(data.summary.likelyMalicious, 2);
    assert.equal(data.summary.review, 2);
    assert.equal(data.summary.infected, 4, "old count kept for existing scripts");
    assert.equal(data.flagged.length, 4);
    assert.deepEqual(data.infected, data.flagged);
    assert.deepEqual(data.flagged.map((r) => r.verdict).sort(), ["likely-malicious", "likely-malicious", "review", "review"]);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("quarantine moves only high and critical unless asked otherwise", async () => {
  const { dir, site, files, vault } = await tree();
  try {
    const result = await scan([site]);
    const q = await quarantineFiles(result.flagged, { vaultDir: vault });
    assert.equal(q.minSeverity, "high");
    assert.deepEqual(q.moved.map((m) => path.basename(m.path)).sort(), ["critical.php", "high.php"]);
    assert.deepEqual(q.skipped.map((s) => `${path.basename(s.path)}:${s.severity}`).sort(), ["low.php:low", "medium.php:medium"]);
    assert.equal(existsSync(files.critical), false);
    assert.equal(existsSync(files.high), false);
    assert.equal(existsSync(files.medium), true, "a medium finding stays in place");
    assert.equal(existsSync(files.low), true, "a low finding stays in place");

    const more = await quarantineFiles((await scan([site])).flagged, { vaultDir: vault, minSeverity: "medium" });
    assert.deepEqual(more.moved.map((m) => path.basename(m.path)), ["medium.php"]);
    const all = await quarantineFiles((await scan([site])).flagged, { vaultDir: vault, minSeverity: "low" });
    assert.deepEqual(all.moved.map((m) => path.basename(m.path)), ["low.php"]);

    const back = await restoreFiles({ vaultDir: vault });
    assert.equal(back.restored.length, 4);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("no vault is made when there is nothing to move", async () => {
  const { dir, site, vault } = await tree(["medium", "low"]);
  try {
    const q = await quarantineFiles((await scan([site])).flagged, { vaultDir: vault });
    assert.equal(q.moved.length, 0);
    assert.equal(q.skipped.length, 2);
    assert.equal(existsSync(vault), false);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("--quarantine leaves medium and low files and says so; --quarantine-severity moves them", async () => {
  const { dir, site, files, vault } = await tree();
  try {
    const dry = run([site, "--quarantine", "--dry-run", "--vault", vault, "--no-banner"]);
    assert.equal(dry.status, 1);
    assert.match(dry.stdout, /Dry run would move 2 file\(s\) into .* and leave 2 file\(s\) with lesser findings in place\. Nothing was changed\./);
    assert.equal(existsSync(files.critical), true);

    const first = run([site, "--quarantine", "--vault", vault, "--no-banner"]);
    assert.equal(first.status, 1);
    assert.match(first.stdout, /critical\.php \(quarantined\)/);
    assert.match(first.stdout, /high\.php \(quarantined\)/);
    assert.match(first.stdout, /medium\.php \(left in place\)/);
    assert.match(first.stdout, /low\.php \(left in place\)/);
    assert.match(first.stdout, /Moved 2 files into the quarantine vault at:/);
    assert.match(first.stdout, /Left 2 files in place: medium and low findings are reasons to look, not proof\./);
    assert.equal(existsSync(files.medium), true);
    assert.equal(existsSync(files.low), true);

    const again = run([site, "--quarantine", "--vault", vault, "--no-banner"]);
    assert.match(again.stdout, /Nothing was moved\. --quarantine moves critical and high findings, and there are none\./);

    const json = JSON.parse(run([site, "--quarantine", "--quarantine-severity", "low", "--vault", vault, "--json"]).stdout);
    assert.equal(json.quarantine.minSeverity, "low");
    assert.equal(json.quarantine.moved.length, 2);
    assert.equal(json.quarantine.leftInPlace.length, 0);
    assert.equal(existsSync(files.medium), false);
    assert.equal(existsSync(files.low), false);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("--quarantine-severity rejects a level that does not exist", () => {
  const r = run([".", "--quarantine", "--quarantine-severity", "everything"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--quarantine-severity must be one of critical, high, medium, low/);
});

test("--help describes what quarantine moves", () => {
  const r = run(["--help"]);
  assert.match(r.stdout, /move critical and high findings into a local vault/);
  assert.match(r.stdout, /--quarantine-severity <level>/);
  assert.doesNotMatch(r.stdout, /move every threat/);
});
