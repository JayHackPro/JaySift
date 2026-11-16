import { test } from "node:test";
import assert from "node:assert/strict";
import { scanBuffer } from "../src/scanner.js";
import { readPhp, holdsNoCode, opensWithPhp } from "../src/php.js";

const idsFor = (name, body) => scanBuffer(name, Buffer.from(body)).map((f) => f.id);

// ----- a folder merely named Media

test("a source folder named Media is not an uploads folder", () => {
  const body = "<?php\nnamespace Acme\\Engine\\Media;\nclass Lazyload {}\n";
  assert.deepEqual(idsFor("/var/www/site/wp-content/plugins/acme/inc/Engine/Media/Lazyload.php", body), []);
  assert.deepEqual(idsFor("/var/www/site/wp-content/plugins/acme/includes/media/class-media.php", body), []);
  assert.deepEqual(idsFor("C:\\sites\\acme\\app\\Media\\Image.php", body), []);
});

test("real upload locations still count, Magento's pub/media among them", () => {
  for (const p of [
    "/var/www/site/wp-content/uploads/2026/x.php",
    "/var/www/site/uploads/x.php",
    "/var/www/shop/pub/media/catalog/x.php",
    "/var/www/site/userfiles/x.php"
  ]) {
    assert.ok(idsFor(p, "<?php echo 1;").includes("heuristic.exec_in_uploads"), p);
  }
});

// ----- a PHP usage example inside a readme

const README =
  "=== Acme Forms ===\nContributors: acme\nTags: forms\nStable tag: 2.3.1\n\nA small contact form plugin.\n\n" +
  "== Installation ==\n\n1. Upload the folder.\n2. Place `<?php echo do_shortcode( '[acme_form]' ); ?>` in a template.\n\n" +
  "<?php\nif ( function_exists( 'acme_form' ) ) {\n    acme_form( 12 );\n}\n?>\n\n== Changelog ==\n\n* Fix: keeps values after a failed submit.\n";

test("a readme that shows a PHP usage example is not PHP hidden in a document", () => {
  assert.deepEqual(idsFor("wp-content/plugins/acme/readme.txt", README), []);
  assert.deepEqual(idsFor("docs/usage.txt", "Usage notes for the theme.\n".repeat(6) + "Call <?= acme_title() ?> in the header.\n"), []);
});

test("a script saved under a text name is still caught, and read as PHP", () => {
  const top = idsFor("notes.txt", "<?php eval($_POST['x']); ?>");
  assert.ok(top.includes("heuristic.php_in_media"));
  assert.ok(top.includes("php.eval_user_input"), "a .txt that opens with a PHP tag gets the PHP rules");
  assert.ok(idsFor("avatar.txt", "GIF89a<?php system($_GET['c']); ?>").includes("heuristic.php_in_media"));
  const padded = "This file is a log.\n".repeat(5) + "<?php\n" + "$a = strrev('x');\n".repeat(40);
  assert.ok(idsFor("log.txt", padded).includes("heuristic.php_in_media"), "mostly PHP, whatever the first lines say");
});

test("an image with PHP in it is flagged wherever the tag sits", () => {
  const body = Buffer.concat([Buffer.alloc(4096, 0x41), Buffer.from("<?php echo 1; ?>")]);
  assert.ok(scanBuffer("photo.jpg", body).map((f) => f.id).includes("heuristic.php_in_media"));
});

// ----- an index.php that holds only "Silence is golden"

test("an index.php holding only a comment or a guard is not a script planted in uploads", () => {
  const p = "/var/www/site/wp-content/uploads/index.php";
  for (const body of [
    "<?php\n// Silence is golden.\n",
    "<?php // Silence is golden. ?>",
    "<?php\n/**\n * Nothing to see here.\n */\n",
    "<?php # Silence is golden",
    "<?php\n// Silence is golden.\nexit;\n",
    "<?php die(); // no direct access ?>",
    ""
  ]) {
    assert.deepEqual(idsFor(p, body), [], JSON.stringify(body));
    assert.equal(holdsNoCode(body), true, JSON.stringify(body));
  }
});

test("a comment does not excuse code that follows it", () => {
  const p = "/var/www/site/wp-content/uploads/index.php";
  assert.ok(idsFor(p, "<?php\n// Silence is golden.\necho 1;\n").includes("heuristic.exec_in_uploads"));
  assert.ok(idsFor(p, "<?php // Silence is golden. ?><?php echo 1;").includes("heuristic.exec_in_uploads"));
  assert.ok(idsFor(p, "<?php\n// Silence is golden.\n?>\n<form action=\"https://example.invalid/\"></form>").includes("heuristic.exec_in_uploads"));
  assert.equal(holdsNoCode("<?php\n// quiet\n$x = 1;"), false);
});

// ----- patterns that appear only inside comments

test("a dangerous call that is only mentioned in a comment is not a finding", () => {
  const body =
    "<?php\n/**\n * Packed loaders look like eval(base64_decode( ... )) or system($_GET['cmd']).\n */\n" +
    "class Notes {\n    // eval(gzinflate(base64_decode($x))) would be rejected in review.\n" +
    "    public function label() { return 'notes'; } # not create_function( or assert($_POST['x'])\n}\n";
  assert.deepEqual(idsFor("class-notes.php", body), []);
});

test("the same call in code is still a finding, on the right line", () => {
  const body = "<?php\n// eval(base64_decode('x')) is what the next line does.\n\neval(base64_decode('ZWNobyAxOw=='));\n";
  const found = scanBuffer("x.php", Buffer.from(body)).find((f) => f.id === "php.eval_decode");
  assert.ok(found);
  assert.equal(found.line, 4);
  assert.equal(found.matches, 1, "the comment on line 2 is not counted");
  assert.match(found.evidence, /^eval\(base64_decode/);
});

test("a comment between a function name and its bracket no longer hides the call", () => {
  assert.ok(idsFor("x.php", "<?php eval/**/(base64_decode/**/('ZWNobyAxOw=='));").includes("php.eval_decode"));
  assert.ok(idsFor("x.php", "<?php system/* x */ ( $_GET['c'] );").includes("php.exec_user_input"));
  assert.ok(idsFor("x.php", "<?php eval // why\n ($_POST['c']);").includes("php.eval_user_input"));
});

test("a shell's own banner comment is still a fingerprint", () => {
  assert.ok(idsFor("x.php", "<?php\n/* c99shell v.1.0 */\n$x = 1;").includes("shell.c99"));
  assert.ok(idsFor("x.php", "<?php\n// Hacked By Example Crew\n$x = 1;").includes("shell.generic_banner"));
});

// ----- the reader must not be talked into hiding code

test("text that only looks like a comment does not hide the code after it", () => {
  const hides = (body) => !idsFor("x.php", body).includes("php.eval_user_input");
  // "//" inside strings
  assert.equal(hides("<?php $u = \"http://example.com\"; eval($_POST[1]);"), false);
  assert.equal(hides("<?php $u = 'a//b'; eval($_POST[1]);"), false);
  // a line that starts with "//" but sits inside a multi-line string
  assert.equal(hides("<?php $x = \"\n// \"; eval($_POST['c']); $y = \"\n\";"), false);
  // quotes nested in {$...} do not end the string
  assert.equal(hides("<?php $s = \"{$a[\"//\"]}\"; eval($_POST[1]);"), false);
  // comment markers inside heredoc and nowdoc text
  assert.equal(hides("<?php $a = <<<X\n/*\nX;\neval($_POST['c']);\n$b = \"*/\";"), false);
  assert.equal(hides("<?php $a = <<<'X'\n// {$a\nX;\neval($_POST['c']);"), false);
  // a closing tag ends a line comment
  assert.equal(hides("<?php // note ?><?php eval($_POST[1]);"), false);
  // an attribute is not a comment
  assert.equal(hides("<?php #[Route('/x')] eval($_POST[1]);"), false);
});

test("where PHP versions or settings read a file differently, the raw text is matched too", () => {
  const ids = (body) => idsFor("x.php", body);
  // Closed the PHP 7.3 way; on older PHP the heredoc runs on and the eval is live.
  assert.ok(ids("<?php $a = <<<X\n X /*\nX;\neval($_POST[1]); //*/").includes("php.eval_user_input"));
  assert.equal(readPhp("<?php $a = <<<X\n X /*\nX;\neval($_POST[1]); //*/").sure, false);
  // Short open tags: on or off changes where PHP starts.
  assert.ok(ids("<? $a = \"<?php /*\"; eval($_POST[1]); $b = \"*/\"; ?>").includes("php.eval_user_input"));
  // A comment or string that never ends.
  assert.ok(ids("<?php /* eval($_POST[1]);").includes("php.eval_user_input"));
  assert.equal(readPhp("<?php $a = 'never closed").sure, false);
});

test("the reader keeps length and line breaks, and leaves strings and HTML alone", () => {
  const body = "<p>// not PHP</p>\n<?php\n/* a\n b */ $s = '/* kept */'; // gone\n?>\n<!-- /* kept */ -->\n";
  const { masked, sure } = readPhp(body);
  assert.equal(sure, true);
  assert.equal(masked.length, body.length);
  assert.equal(masked.split("\n").length, body.split("\n").length);
  assert.ok(masked.includes("<p>// not PHP</p>"));
  assert.ok(masked.includes("'/* kept */'"));
  assert.ok(masked.includes("<!-- /* kept */ -->"));
  assert.ok(!masked.includes("gone"));
  assert.ok(!masked.includes(" b */"));
});

test("a 5 MB comment is read without trouble", () => {
  const body = "<?php\n/*" + "A".repeat(5 * 1024 * 1024) + "*/\neval($_POST['x']);\n";
  const started = Date.now();
  assert.ok(idsFor("big.php", body).includes("php.eval_user_input"));
  assert.ok(Date.now() - started < 5000);
});

// ----- a file that opens with a PHP tag is PHP, whatever it is called

test("a PHP script under another name is read as PHP", () => {
  assert.ok(idsFor("includes/db.inc", "<?php eval($_POST['x']);").includes("php.eval_user_input"));
  assert.ok(idsFor("cache/data.bak", "<?php\neval($_POST['x']);").includes("php.eval_user_input"));
  assert.ok(idsFor("cache/.session", "\uFEFF\n<?php eval($_POST['x']);").includes("php.eval_user_input"));
  assert.equal(opensWithPhp("#!/usr/bin/env php\n<?php echo 1;"), true);
});

test("documentation that shows PHP is not read as a PHP script", () => {
  const md = "# Security notes\n\nNever do this:\n\n```php\n<?php\neval($_GET['code']);\n```\n";
  assert.deepEqual(idsFor("docs/security.md", md), []);
  assert.equal(opensWithPhp(md), false);
  assert.deepEqual(idsFor("includes/form.inc", "<?php\nfunction acme_validate( $v ) { return ! empty( $v ); }\n"), []);
});
