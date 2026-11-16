import { test } from "node:test";
import assert from "node:assert/strict";
import { scanBuffer } from "../src/scanner.js";
import { kindForPath } from "../src/rules.js";

const scanned = (name, body) => scanBuffer(name, Buffer.from(body));
const idsFor = (name, body) => scanned(name, body).map((f) => f.id);
const php = (...lines) => "<?php\n" + lines.join("\n") + "\n";

// ----- a decoded or request value copied into a variable, then run

test("a decoded payload put in a variable and then passed to eval is caught", () => {
  const found = scanned("x.php", php("$c = base64_decode('ZWNobyAxOw==');", "eval($c);")).find((f) => f.id === "php.eval_via_variable");
  assert.ok(found);
  assert.equal(found.severity, "high");
  assert.equal(found.line, 3);
  assert.equal(found.evidence, "eval($c);");
  assert.ok(idsFor("x.php", php("$z = gzinflate(str_rot13($blob));", "assert($z);")).includes("php.eval_via_variable"));
  assert.ok(idsFor("x.php", php("$c = $_POST['c'];", "eval('?>' . $c);")).includes("php.eval_via_variable"));
});

test("a request value put in a variable and then run as a command is caught", () => {
  for (const body of [
    php("$c = $_GET['c'];", "system($c);"),
    php("$c=$_REQUEST['c'];passthru($c);"),
    php("$cmd = $_COOKIE['k'];", "$h = popen($cmd, 'r');"),
    php("$c = file_get_contents('php://input');", "shell_exec($c);"),
    php("$c = $_SERVER['HTTP_X_RUN'];", "\\exec($c);"),
    php("$c = base64_decode('bHM=');", "system($c);"),
    php("$c = 'ls ';", "$c .= $_GET['dir'];", "system($c);")
  ]) {
    assert.ok(idsFor("x.php", body).includes("php.exec_via_variable"), body);
  }
});

test("the value is followed through a second variable and out of a foreach", () => {
  assert.ok(idsFor("x.php", php("$a = $_GET['c'];", "$b = $a;", "system($b);")).includes("php.exec_via_variable"));
  assert.ok(idsFor("x.php", php("foreach ($_POST as $k => $v) { eval($v); }")).includes("php.eval_via_variable"));
});

test("ordinary code that decodes data or runs a prepared command is left alone", () => {
  for (const body of [
    // decoded as data, never run
    php("$data = base64_decode($row->image);", "$img = imagecreatefromstring($data);"),
    // escaped before it reaches the command
    php("$name = sanitize_file_name($_POST['file']);", "$cmd = 'convert ' . escapeshellarg($name);", "exec($cmd, $out, $code);"),
    php("$dir = $_POST['dir'];", "exec('du -sh ' . escapeshellarg($dir), $out);"),
    php("$id = (int) $_GET['id'];", "system('report ' . $id);"),
    // a clean value replaces the request value before the call
    php("$c = $_GET['c'];", "$c = 'uptime';", "system($c);"),
    // the decoded variable is only where exec() writes its output
    php("$output = base64_decode($stored);", "exec('uptime', $output);"),
    // a database method called exec, and a longer function name
    php("$sql = 'DELETE FROM t WHERE id = ' . $_POST['id'];", "$db->exec($sql);"),
    php("$c = $_GET['c'];", "my_system($c);", "Runner::exec($c);"),
    // filled in one function, used in another
    php("function a() { $c = $_GET['c']; return 1; }", "function b($c) { system($c); }")
  ]) {
    assert.deepEqual(idsFor("x.php", body), [], body);
  }
});

test("a call made straight on request input is reported once, by its own rule", () => {
  const ids = idsFor("x.php", php("$c = $_GET['c'];", "system($_GET['c']);"));
  assert.ok(ids.includes("php.exec_user_input"));
  assert.ok(!ids.includes("php.exec_via_variable"));
});

// ----- backtick execution

test("backticks built from request input are a critical finding", () => {
  for (const body of [php("$out = `{$_REQUEST['c']}`;"), php("echo `$_GET[c]`;"), php("print(`ls {$_POST['d']}`);")]) {
    const found = scanned("x.php", body).find((f) => f.id === "php.backtick_user_input");
    assert.ok(found, body);
    assert.equal(found.severity, "critical");
  }
});

test("backticks that run a followed variable are caught, and any other backtick command is worth a look", () => {
  const followed = idsFor("x.php", php("$c = $_POST['c'];", "$out = `$c`;"));
  assert.deepEqual(followed, ["php.exec_via_variable"]);
  const plain = scanned("x.php", php("$v = trim(`git describe --tags`);"));
  assert.deepEqual(plain.map((f) => `${f.id}:${f.severity}`), ["php.backtick_exec:medium"]);
});

test("backticks that are not PHP commands are ignored", () => {
  for (const body of [
    php("$sql = \"SELECT `id`, `email` FROM `{$wpdb->prefix}entries`\";"),
    php("$sql = 'SELECT `id` FROM `t`';"),
    php("$help = <<<TXT", "Run `wp acme sync` to refresh.", "TXT;"),
    php("/**", " * Values come from `$_POST` and `$_GET`.", " */", "// run `make` first", "function f() {}"),
    "<?php get_header(); ?>\n<script>const label = `Open ${name} menu`;</script>\n"
  ]) {
    assert.deepEqual(idsFor("x.php", body), [], body);
  }
});

// ----- include of request input

test("include of raw request input is caught", () => {
  for (const body of [
    php("include($_GET['page']);"),
    php("require_once $_REQUEST['f'];"),
    php("include_once( $_POST['tpl'] . '.php' );"),
    php("include 'php://input';"),
    php("@include($_COOKIE['p']);")
  ]) {
    const found = scanned("x.php", body).find((f) => f.id === "php.include_user_input");
    assert.ok(found, body);
    assert.equal(found.severity, "high");
  }
});

test("ordinary includes are left alone", () => {
  for (const body of [
    php("include __DIR__ . '/partials/header.php';"),
    php("require_once ABSPATH . 'wp-admin/includes/file.php';"),
    php("$tab = sanitize_key($_GET['tab']);", "include ACME_DIR . 'tabs/' . $tab . '.php';"),
    php("$view->include($_GET['t']);", "Loader::require($_GET['t']);"),
    php("// include($_GET['page']) is the mistake this file avoids")
  ]) {
    assert.deepEqual(idsFor("x.php", body), [], body);
  }
});

// ----- a malicious .htaccess

test(".htaccess and PHP ini files are known by name", () => {
  assert.equal(kindForPath("/var/www/site/.htaccess"), "htaccess");
  assert.equal(kindForPath("C:\\sites\\acme\\uploads\\.htaccess"), "htaccess");
  assert.equal(kindForPath(".htaccess"), "htaccess");
  assert.equal(kindForPath("/var/www/site/.user.ini"), "phpini");
  assert.equal(kindForPath("/var/www/site/php.ini"), "phpini");
  assert.equal(kindForPath("/var/www/site/settings.ini"), "other");
  assert.equal(kindForPath("includes/db.inc"), "php");
});

test("an .htaccess that runs images as PHP is a critical finding", () => {
  for (const body of [
    "AddType application/x-httpd-php .jpg\n",
    "AddHandler php5-script .gif .png\n",
    "  AddHandler cgi-script .txt\n",
    "<FilesMatch \"\\.(jpg|png)$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n",
    "<Files \"logo.ico\">\nForceType application/x-httpd-php\n</Files>\n"
  ]) {
    const found = scanned("uploads/.htaccess", body).find((f) => f.id === "server.php_handler_on_media");
    assert.ok(found, body);
    assert.equal(found.severity, "critical");
  }
});

test("an .htaccess that redirects visitors from search engines is caught, on the line of the condition", () => {
  const body =
    "RewriteEngine On\nRewriteCond %{HTTP_REFERER} (google|bing|yahoo)\\. [NC,OR]\nRewriteCond %{HTTP_USER_AGENT} (android|iphone) [NC]\n" +
    "RewriteRule ^(.*)$ http://example.invalid/in.php?u=$1 [R=302,L]\n";
  const found = scanned(".htaccess", body).find((f) => f.id === "server.search_redirect");
  assert.ok(found);
  assert.equal(found.severity, "high");
  assert.equal(found.line, 2);
  assert.ok(idsFor(".htaccess", "RewriteCond %{HTTP_REFERER} .*google.* [NC]\nRewriteRule .* cache/a.php [L]\n").includes("server.search_redirect"));
});

test("auto_prepend_file is worth a look, and a disguised target is a high finding", () => {
  const sev = (name, body) => scanned(name, body).map((f) => `${f.id}:${f.severity}`);
  assert.deepEqual(sev(".htaccess", "php_value auto_prepend_file /home/acme/public_html/lib/boot.php\n"), ["server.auto_prepend:medium"]);
  assert.deepEqual(sev(".user.ini", "auto_append_file = \"/home/acme/setup.php\"\n"), ["server.auto_prepend:medium"]);
  for (const [name, body] of [
    [".htaccess", "php_value auto_prepend_file \"/home/acme/public_html/wp-content/uploads/2026/photo.jpg\"\n"],
    [".htaccess", "php_admin_value auto_prepend_file /tmp/.sess_a1\n"],
    [".user.ini", "auto_prepend_file=/home/acme/public_html/favicon.ico\n"],
    ["php.ini", "auto_prepend_file = 'data:text/plain;base64,PD9waHA='\n"],
    [".user.ini", "auto_prepend_file = /home/acme/public_html/wp-content/cache/object.php\n"]
  ]) {
    assert.deepEqual(sev(name, body), ["server.auto_prepend_hidden:high"], body);
  }
});

test("ordinary server configuration is left alone", () => {
  const wordpress =
    "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\n" +
    "RewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n";
  for (const body of [
    wordpress,
    "<IfModule mime_module>\n  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml\n</IfModule>\n",
    "<FilesMatch \"\\.(php4|php5|php3|php2|php|phtml)$\">\nSetHandler application/x-lsphp81\n</FilesMatch>\n",
    "# Wordfence WAF\n<IfModule mod_php.c>\n  php_value auto_prepend_file '/home/acme/public_html/wordfence-waf.php'\n</IfModule>\n",
    "php_value auto_prepend_file none\n",
    "RewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n",
    // hotlink protection: the search engines are let through, not caught
    "RewriteCond %{HTTP_REFERER} !^$\nRewriteCond %{HTTP_REFERER} !google\\. [NC]\nRewriteRule \\.(jpe?g|png)$ https://example.com/no-hotlink.png [R,L]\n",
    // a referrer condition that only blocks
    "RewriteCond %{HTTP_REFERER} (semalt|buttons-for-website)\\. [NC]\nRewriteRule .* - [F]\n",
    "<FilesMatch \"\\.(jpe?g|png|gif)$\">\n  Header set Cache-Control \"max-age=31536000\"\n</FilesMatch>\n",
    "# AddType application/x-httpd-php .jpg\n  # php_value auto_prepend_file /tmp/x\n",
    "AddType image/svg+xml .svg\nAddType text/css .css\n"
  ]) {
    assert.deepEqual(idsFor(".htaccess", body), [], body);
  }
  assert.deepEqual(idsFor(".user.ini", "; Wordfence WAF\nauto_prepend_file = '/home/acme/public_html/wordfence-waf.php'\n; auto_prepend_file = /tmp/x\nupload_max_filesize = 32M\n"), []);
});

test("--ignore-rule silences the new checks like any other", () => {
  const body = php("$c = $_GET['c'];", "system($c);");
  const ids = scanBuffer("x.php", Buffer.from(body), { ignoreRules: new Set(["php.exec_via_variable"]) }).map((f) => f.id);
  assert.deepEqual(ids, []);
  const ht = scanBuffer(".htaccess", Buffer.from("AddType application/x-httpd-php .jpg\n"), { ignoreRules: new Set(["server.php_handler_on_media"]) });
  assert.deepEqual(ht, []);
});
