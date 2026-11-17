import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { scan } from "../src/scanner.js";
import { CORPUS, buildCorpus, measure } from "./corpus/corpus.mjs";

// The corpus is harmless stand-ins, see test/corpus/corpus.mjs. These tests
// hold the scanner to what it does on them today. When detection improves,
// change a file's `expect` there and the counts here.

test("the corpus: what is caught, what is missed, what is wrongly flagged", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jaysift-corpus-test-"));
  try {
    const { root, manifest } = await buildCorpus(dir);
    const listed = JSON.parse(await fs.readFile(manifest, "utf8"));
    assert.deepEqual(listed.groups, { clean: 29, textbook: 29, disguised: 33 });
    assert.equal(new Set(CORPUS.map((f) => f.path)).size, CORPUS.length, "two corpus files share a path");
    assert.equal(listed.files.length, CORPUS.length);

    const byDefault = await measure(root, scan);
    const everything = await measure(root, scan, { includeDirs: ["all"], maxBytes: 10 * 1024 * 1024 });

    // The base set: the files every earlier figure was measured on.
    const base = byDefault.sets.base;
    // Every plain technique is caught.
    assert.deepEqual(base.textbook, { total: 29, flagged: 29, serious: 26 });
    // Seven of the sixteen light disguises are caught, nine once skipped
    // folders and large files are scanned. The rest are known gaps.
    assert.deepEqual(base.disguised, { total: 16, flagged: 7, serious: 7 });
    assert.deepEqual(everything.sets.base.disguised, { total: 16, flagged: 9, serious: 9 });
    // No clean file is called likely malicious. Three are still worth-a-look.
    assert.deepEqual(base.clean, { total: 24, flagged: 3, serious: 0 });

    // The files added with the calls-by-name checks, counted on their own.
    // None of the seventeen disguises is caught yet: they are the gap to close.
    // None of the five clean look-alikes is flagged at all.
    const added = byDefault.sets["calls-by-name"];
    assert.deepEqual(added.disguised, { total: 17, flagged: 0, serious: 0 });
    assert.deepEqual(everything.sets["calls-by-name"].disguised, { total: 17, flagged: 0, serious: 0 });
    assert.deepEqual(added.clean, { total: 5, flagged: 0, serious: 0 });

    const serious = (top) => top === "critical" || top === "high";
    const full = new Map(everything.files.map((f) => [f.path, f]));
    for (const f of byDefault.files) {
      const label = `${f.path} (${f.technique})`;
      if (f.expect === "quiet") assert.equal(f.top, null, `clean file flagged: ${label}`);
      else if (f.expect === "review") assert.ok(!serious(f.top), `clean file called likely malicious: ${label}`);
      else if (f.expect === "flag") assert.ok(f.top, `not caught: ${label}`);
      else if (f.expect === "missed") assert.equal(full.get(f.path).top, null, `now caught, update the corpus: ${label}`);
      else if (f.expect === "included") {
        assert.equal(f.top, null, `caught by default, update the corpus: ${label}`);
        assert.ok(full.get(f.path).top, `not caught even when included: ${label}`);
      } else assert.fail(`unknown expectation on ${label}`);
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
