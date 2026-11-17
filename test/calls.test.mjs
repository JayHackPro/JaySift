import { test } from "node:test";
import assert from "node:assert/strict";
import { scanBuffer } from "../src/scanner.js";

// Every body here is text handed to the scanner. Nothing in this file is run
// as PHP, and no callback or eval in these strings is ever called.

const scanned = (name, body, options) => scanBuffer(name, Buffer.from(body), options);
const idsFor = (name, body) => scanned(name, body).map((f) => f.id);
const php = (...lines) => "<?php\n" + lines.join("\n") + "\n";

const CALL = "php.call_by_name";
const CALLBACK = "php.callback_by_name";
const flagged = (body, id) => idsFor("x.php", body).includes(id);
const quiet = (body) => !flagged(body, CALL) && !flagged(body, CALLBACK);

// ----- a name joined from pieces, then called

test("a command function's name joined from pieces and called on request input is caught", () => {
  const found = scanned("x.php", php("$f = 'sys' . 'tem';", "$f($_GET['c']);")).find((f) => f.id === CALL);
  assert.ok(found);
  assert.equal(found.severity, "high");
  assert.equal(found.category, "exec");
  assert.equal(found.line, 3);
  assert.equal(found.evidence, "$f($_GET['c']);");
});

test("the ways a name is joined: dots, .=, implode, join, chr, brackets", () => {
  for (const body of [
    php("$f = 'sh' . 'ell' . '_' . 'exec';", "echo $f($_POST['c']);"),
    php("$n = 'pass';", "$n .= 'thru';", "$n($_REQUEST['c']);"),
    php("$f = implode('', array('sh', 'ell', '_ex', 'ec'));", "$f($_GET['c']);"),
    php("$f = join('', ['pro', 'c_o', 'pen']);", "$f($_GET['c'], $d, $p);"),
    php("$f = implode('_', array('shell', 'exec'));", "$f($_GET['c']);"),
    php("$f = chr(115) . chr(0x79) . chr(0163) . 'tem';", "$f($_COOKIE['k']);"),
    php("$a = 'sys';", "$b = 'tem';", "$f = $a . $b;", "$f($_GET['c']);"),
    php("$f = ('sys' . 'tem');", "$f($_GET['c']);"),
    php("('sys' . 'tem')($_GET['c']);"),
    php("if ($ok) { echo 1; }", "('sys' . 'tem')($_GET['c']);"),
    php("function run() { return ('pass' . 'thru')($_GET['c']); }")
  ]) {
    assert.ok(flagged(body, CALL), body);
  }
});

test("a name held whole in a string is caught too, however the string is written", () => {
  for (const body of [
    php("$f = 'system';", "$f($_GET['c']);"),
    php('$f = "system";', "$f($_GET['c']);"),
    php('$f = "\\x73ystem";', "$f($_GET['c']);"),
    php('$f = "\\163ystem";', "$f($_GET['c']);"),
    php("$f = 'SYSTEM';", "$f($_GET['c']);"),
    php("$f = '\\\\system';", "$f($_GET['c']);"),
    php("'system'($_GET['c']);"),
    php("$f = 'assert';", "$f($_POST['x']);")
  ]) {
    assert.ok(flagged(body, CALL), body);
  }
});

test("the request value is followed through a variable, a foreach and a ternary", () => {
  for (const body of [
    php("$cmd = $_POST['cmd'];", "$f = 'sys' . 'tem';", "$f($cmd);"),
    php("$a = $_GET['c'];", "$b = $a;", "$f = 'sys' . 'tem';", "$f($b);"),
    php("$c = isset($_GET['c']) ? $_GET['c'] : '';", "$f = 'pass' . 'thru';", "$f($c);"),
    php("$f = 'sys' . 'tem';", "foreach ($_POST as $k => $v) { $f($v); }"),
    php("$c = file_get_contents('php://input');", "$f = 'sys' . 'tem';", "$f($c);"),
    php("$c = $_SERVER['HTTP_X_RUN'];", "$f = 'sys' . 'tem';", "$f($c);"),
    php("$c = 'ls ';", "$c .= $_GET['dir'];", "$f = 'sys' . 'tem';", "$f($c);")
  ]) {
    assert.ok(flagged(body, CALL), body);
  }
});

test("a request value put into an array element makes the array carry it", () => {
  assert.ok(flagged(php("$a = array();", "$a[] = $_POST['a'];", "usort($a, 'system');"), CALLBACK));
  assert.ok(flagged(php("$a = array();", "$a['cmd'] = $_GET['c'];", "array_map('system', $a);"), CALLBACK));
  assert.ok(quiet(php("$a = array();", "$a[] = intval($_GET['n']);", "usort($a, 'system');")));
  assert.ok(quiet(php("$a = array();", "$a[$_GET['k']] = 'fixed';", "usort($a, 'system');")));
});

// ----- a name passed as a callback

test("a command function passed by name as a callback on request input is caught", () => {
  const found = scanned("x.php", php("array_filter(array($_GET['c']), 'system');")).find((f) => f.id === CALLBACK);
  assert.ok(found);
  assert.equal(found.severity, "high");
  assert.equal(found.line, 2);
  for (const body of [
    php("call_user_func('system', $_GET['c']);"),
    php("call_user_func_array('passthru', array($_POST['c']));"),
    php("array_map('system', array($_GET['c']));"),
    php("array_walk($_POST, 'assert');"),
    php("$a = array($_POST['a'], $_POST['b']);", "usort($a, 'system');"),
    php("$a = $_GET;", "uasort($a, 'system');"),
    php("array_reduce($_GET, 'system');"),
    php("register_shutdown_function('system', $_GET['c']);"),
    php("register_tick_function('shell_exec', $_GET['c']);"),
    php("function r() { return \\call_user_func('system', $_GET['c']); }"),
    php("$in = $_GET['in'];", "array_map('system', array($in));")
  ]) {
    assert.ok(flagged(body, CALLBACK), body);
  }
});

test("the callback's name may be joined, or held in a variable", () => {
  for (const body of [
    php("call_user_func('ass' . 'ert', $_POST['x']);"),
    php("$cb = 'sys' . 'tem';", "array_map($cb, array($_GET['c']));"),
    php("$cb = implode('', ['pass', 'thru']);", "call_user_func($cb, $_GET['c']);"),
    php("array_filter(array($_GET['c']), chr(101) . 'xec');")
  ]) {
    assert.ok(flagged(body, CALLBACK), body);
  }
});

test("a command function named as a filter_var callback is caught", () => {
  assert.ok(flagged(php("filter_var($_REQUEST['c'], FILTER_CALLBACK, array('options' => 'assert'));"), CALLBACK));
  assert.ok(flagged(php("$o = 'sys' . 'tem';", "filter_var($_GET['c'], FILTER_CALLBACK, ['options' => $o]);"), CALLBACK));
  assert.ok(quiet(php("filter_var($_GET['c'], FILTER_CALLBACK, array('options' => 'trim'));")));
  assert.ok(quiet(php("filter_var($_GET['c'], FILTER_VALIDATE_INT, array('options' => 'system'));")));
});

// ----- where code ends: comments and strings

test("a call by name written inside a comment is not code", () => {
  assert.ok(quiet(php("// $f = 'sys' . 'tem'; $f($_GET['c']);", "echo $_GET['q'];")));
  assert.ok(quiet(php("# array_filter(array($_GET['c']), 'system');", "echo $_GET['q'];")));
  assert.ok(quiet(php("/*", " * $f = 'sys' . 'tem';", " * $f($_GET['c']);", " */", "echo $_GET['q'];")));
  // A name left in a comment is not a name the code holds.
  assert.ok(quiet(php("// $f = 'sys' . 'tem';", "$f($_GET['c']);")));
});

test("a comment between the pieces, or before the bracket, hides nothing", () => {
  assert.ok(flagged(php("$f = 'sys' /* a */ . 'tem';", "$f /* b */ ($_GET['c']);"), CALL));
  assert.ok(flagged(php("$f = 'sys' . // first half", "  'tem';", "$f(", "  # the request", "  $_GET['c']);"), CALL));
  assert.ok(flagged(php("array_map(/* cb */ 'sys' . 'tem', /* data */ $_GET);"), CALLBACK));
});

test("a call by name written inside a string is not code", () => {
  assert.ok(quiet(php("$help = \"Never write \\$f = 'sys' . 'tem'; \\$f(\\$_GET['c']); in a template.\";", "echo $help . $_GET['q'];")));
  assert.ok(quiet(php("$t = 'array_filter(array($_GET[\"c\"]), \"system\");';", "echo $t . $_GET['q'];")));
  assert.ok(quiet(php("$doc = <<<'TXT'", "$f = 'sys' . 'tem';", "$f($_GET['c']);", "usort($a, 'system');", "TXT;", "echo $doc . $_GET['q'];")));
  assert.ok(quiet(php("$doc = <<<TXT", "call_user_func('system', \\$_GET['c']);", "TXT;", "echo $doc . $_GET['q'];")));
  // A string that only mentions the pieces does not join them.
  assert.ok(quiet(php("$f = \"'sys' . 'tem'\";", "$f($_GET['c']);")));
});

test("a string with a variable inside it is not treated as a fixed name", () => {
  assert.ok(quiet(php('$f = "sys$tem";', "$f($_GET['c']);")));
  assert.ok(quiet(php('$f = "{$prefix}system";', "$f($_GET['c']);")));
});

// ----- where a variable's value ends: functions and reassignment

test("a name is not followed from one function into another", () => {
  assert.ok(quiet(php("function a() { $f = 'sys' . 'tem'; return $f; }", "function b($f) { return $f($_GET['q']); }")));
  assert.ok(quiet(php("$f = 'sys' . 'tem';", "function b($f) { return $f($_GET['q']); }")));
  assert.ok(quiet(php("function a() { $f = 'sys' . 'tem'; }", "$f($_GET['q']);")));
  assert.ok(quiet(php("class A { function a() { $f = 'system'; } function b($f) { $f($_GET['q']); } }")));
});

test("use and global carry a name into a function, because they say so", () => {
  assert.ok(flagged(php("$f = 'sys' . 'tem';", "$run = function () use ($f) { return $f($_POST['c']); };"), CALL));
  assert.ok(flagged(php("$f = 'sys' . 'tem';", "function go() { global $f; $f($_GET['c']); }"), CALL));
  assert.ok(flagged(php("$f = 'sys' . 'tem';", "$run = fn($x) => $f($_GET['c']);"), CALL));
  // A closure that does not ask for the variable does not get it.
  assert.ok(quiet(php("$f = 'sys' . 'tem';", "$run = function ($f) { return $f($_POST['c']); };")));
});

test("a later assignment replaces the name", () => {
  assert.ok(quiet(php("$f = 'sys' . 'tem';", "$f = 'trim';", "echo $f($_GET['c']);")));
  assert.ok(quiet(php("$f = 'sys' . 'tem';", "$f = get_formatter();", "echo $f($_GET['c']);")));
  assert.ok(quiet(php("$fn = 'shell' . '_exec';", "$can = function_exists($fn);", "$fn = 'esc_html';", "echo $fn($_GET['label']);")));
  assert.ok(flagged(php("$f = 'trim';", "$f = 'sys' . 'tem';", "echo $f($_GET['c']);"), CALL));
});

test("an assignment inside a branch only adds a possibility", () => {
  for (const body of [
    php("$f = 'sys' . 'tem';", "if (isset($_GET['plain'])) { $f = 'trim'; }", "echo $f($_GET['c']);"),
    php("$f = 'sys' . 'tem';", "if (0) $f = 'trim';", "echo $f($_GET['c']);"),
    php("$f = 'sys' . 'tem';", "if ($a) :", "  $f = 'trim';", "endif;", "echo $f($_GET['c']);"),
    php("if ($a) { $f = 'trim'; } else { $f = 'sys' . 'tem'; }", "echo $f($_GET['c']);"),
    php("$f = 'trim';", "while ($a) { $f = 'pass' . 'thru'; }", "echo $f($_GET['c']);")
  ]) {
    assert.ok(flagged(body, CALL), body);
  }
  // Replaced again after the branch, in the open: the name is gone.
  assert.ok(quiet(php("$f = 'trim';", "if ($a) { $f = 'sys' . 'tem'; }", "$f = 'esc_html';", "echo $f($_GET['c']);")));
});

test("a class property's default is not a variable in the code around it", () => {
  assert.ok(quiet(php("class A { public $f = 'system'; }", "$f = get_cb();", "$f($_GET['c']);")));
  assert.ok(quiet(php("class A { public $f = 'system'; }", "$f($_GET['c']);")));
});

// ----- clean look-alikes

test("harmless callbacks on request input stay quiet", () => {
  assert.deepEqual(
    idsFor(
      "x.php",
      php(
        "$tags = array_map('trim', (array) $_POST['tags']);",
        "$ids = array_filter((array) $_GET['ids'], 'is_numeric');",
        "usort($tags, 'strcasecmp');",
        "$title = call_user_func('sanitize_text_field', $_POST['title']);",
        "$rows = array_map(array($table, 'exec'), (array) $_POST['rows']);",
        "register_shutdown_function('acme_forms_flush', $_GET['form']);",
        "array_map('acme_system_row', (array) $_POST['rows']);",
        "call_user_func('Acme_Report::system', $_GET['tab']);"
      )
    ),
    []
  );
});

test("harmless names joined from pieces stay quiet", () => {
  assert.deepEqual(
    idsFor(
      "x.php",
      php(
        "$action = isset($_GET['action']) ? $_GET['action'] : 'list';",
        "$handler = 'acme_forms_handle_' . $action;",
        "if (function_exists($handler)) { $handler($_GET); }",
        "$fn = 'str' . 'toupper';",
        "echo esc_html($fn($_GET['label']));",
        "$method = 'get_' . 'title';",
        "echo esc_html($form->$method());"
      )
    ),
    []
  );
});

test("a method, a static method or a class of the same name is not the function", () => {
  assert.deepEqual(
    idsFor(
      "x.php",
      php(
        "$section = 'system';",
        "echo esc_html($report->$section($_GET['tab']));",
        "echo esc_html($report?->$section($_GET['tab']));",
        "echo esc_html(Acme_Report::$section($_GET['tab']));",
        "$panel = new $section($_GET['tab']);",
        "call_user_func(array($report, 'system'), $_GET['tab']);",
        "$report->{$section}($_GET['tab']);"
      )
    ),
    []
  );
});

test("without request input, or once it is escaped, nothing is reported", () => {
  assert.ok(quiet(php("$f = 'sys' . 'tem';", "$f('uptime');")));
  assert.ok(quiet(php("$f = 'sys' . 'tem';", "$f($internal);")));
  assert.ok(quiet(php("array_map('system', $internal);")));
  assert.ok(quiet(php("$f = 'sys' . 'tem';", "$f(escapeshellarg($_GET['c']));")));
  assert.ok(quiet(php("array_map('system', array(intval($_GET['n'])));")));
  assert.ok(quiet(php("$n = (int) $_GET['n'];", "$f = 'sys' . 'tem';", "$f($n);")));
  assert.ok(quiet(php("$f = 'sys' . 'tem';", "$ok = isset($_GET['c']);", "$f($ok);")));
});

test("declaring a function named like a callback helper is not a call to it", () => {
  assert.ok(quiet(php("function array_map($cb, $data) { return $data; }", "echo $_GET['q'];")));
  assert.ok(quiet(php("$x = new call_user_func('system', $_GET['c']);")));
});

// ----- the edges of the reader

test("a file the reader is unsure of is still read", () => {
  // Short open tags only run where they are switched on.
  assert.ok(flagged("<?\n$f = 'sys' . 'tem';\n$f($_GET['c']);\n", CALL));
  assert.ok(flagged("<?\narray_filter(array($_GET['c']), 'system');\n?>\n", CALLBACK));
});

test("a name set in one PHP block is still held in the next", () => {
  assert.ok(flagged("<?php $f = 'sys' . 'tem' ?>\n<p>Don't mind this.</p>\n<?php $f($_GET['c']); ?>\n", CALL));
  // The apostrophe in the HTML between the blocks is not a string.
  assert.ok(quiet("<?php $f = 'trim' ?>\n<p>Don't 'sys' . 'tem' here.</p>\n<?php echo $f($_GET['c']); ?>\n"));
});

test("a file that opens with PHP is read whatever it is called", () => {
  assert.ok(idsFor("notes.dat", php("$f = 'sys' . 'tem';", "$f($_GET['c']);")).includes(CALL));
});

test("each finding can be switched off by its id", () => {
  const body = php("$f = 'sys' . 'tem';", "$f($_GET['c']);", "array_map('system', $_GET);");
  assert.deepEqual(idsFor("x.php", body).filter((id) => id === CALL || id === CALLBACK).sort(), [CALL, CALLBACK].sort());
  const left = scanned("x.php", body, { ignoreRules: new Set([CALL]) }).map((f) => f.id);
  assert.ok(!left.includes(CALL));
  assert.ok(left.includes(CALLBACK));
});

test("several calls in one file are one finding with every line", () => {
  const found = scanned("x.php", php("$f = 'sys' . 'tem';", "$f($_GET['a']);", "echo 1;", "$f($_POST['b']);")).find((f) => f.id === CALL);
  assert.equal(found.matches, 2);
  assert.deepEqual(found.lines, [3, 5]);
});

test("broken or odd input is read without failing", () => {
  for (const body of [
    php("$f = 'sys' . 'tem'; $f($_GET['c']"),
    php("}}}} $f = 'sys' . 'tem'; ((( $f($_GET['c']);"),
    php("function ("),
    php("endif; endwhile; else: $_GET"),
    php("$f = 'sys' . ;", "$f($_GET['c']);"),
    php("array_map(", "$_GET"),
    php("$_GET" + "(".repeat(5000)),
    php("$a = $_GET;" + " $a = $a . 'x';".repeat(5000))
  ]) {
    assert.doesNotThrow(() => scanned("x.php", body), body.slice(0, 60));
  }
});

test("a call at the end of a long file of ordinary code is still found", () => {
  const tail = "\n$f = 'sys' . 'tem';\n$f($_GET['c']);\n";
  for (const filler of ["if ($a) { $b = 1; }\n", "$r = x(array_map('trim', $rows));\n", "$a;"]) {
    const body = "<?php\n" + filler.repeat(Math.ceil(600000 / filler.length)) + tail;
    assert.ok(flagged(body, CALL), filler.trim());
  }
});
