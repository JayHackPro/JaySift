/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

import { evidenceAt } from "./heuristics.js";

/**
 * Checks that follow a value for one step.
 *
 * The signature rules catch a dangerous call made directly on request input
 * or on a decoded string: eval($_POST['c']), eval(base64_decode(...)). The
 * lightest disguise is to put the value in a variable first:
 *
 *     $c = $_GET['c'];
 *     system($c);
 *
 * No single line of that is suspicious. These checks note which variables
 * were filled from the request or from a decoder, and report when one of them
 * reaches eval, a shell command, or a pair of backticks.
 *
 * This is name matching, not a full analysis of the program, so its findings
 * are high rather than critical. A value that passed through an escaping or
 * validating function is not followed, and a variable is not followed from
 * one function into the next.
 */

const REQUEST = /\$_(?:GET|POST|REQUEST|COOKIE)\b|php:\/\/input|\$HTTP_RAW_POST_DATA\b|\$_SERVER\s*\[\s*["']HTTP_/i;
const DECODER = /\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin)\s*\(/i;
const SANITIZER = /\b(?:escapeshellarg|escapeshellcmd|intval|floatval|absint|sanitize_\w+|esc_\w+|filter_var|filter_input|preg_quote|basename|md5|sha1|hash|crc32|strlen|count|isset|empty|is_\w+|in_array|array_key_exists|wp_verify_nonce)\s*\(|\(\s*(?:int|integer|float|bool|boolean)\s*\)/i;

const ASSIGN = /\$([A-Za-z_]\w*)\s*(\.?)=(?![=>])\s*([^;]{1,400})/g;
const FOREACH = /\bforeach\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s+as\s+(?:\$\w+\s*=>\s*)?&?\$([A-Za-z_]\w*)/gi;
const FUNCTION = /\bfunction\b[^({;]{0,80}\(/g;
const VARIABLE = /\$([A-Za-z_]\w*)/g;

// A real call, not a method or a longer name: not after ->, ::, $ or a word
// character, and not after a namespace. A lone leading backslash is fine.
const CALL = "(?<![\\w$>:])(?<!\\w\\\\)";
const CODE_SINK = new RegExp(`${CALL}(?:eval|assert)\\s*\\(([^;]{0,160})`, "gi");
// Only the first argument of a command call is the command.
const SHELL_SINK = new RegExp(`${CALL}(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\s*\\(([^,;]{0,160})`, "gi");

const FINDINGS = {
  eval: {
    id: "php.eval_via_variable",
    name: "Decoded or request value run as code through a variable",
    severity: "high",
    category: "backdoor",
    description: "A value taken from the request or from a decoder is put in a variable and then passed to eval. It is the eval-of-a-payload backdoor with one step added to hide it."
  },
  exec: {
    id: "php.exec_via_variable",
    name: "Request or decoded value run as a shell command through a variable",
    severity: "high",
    category: "exec",
    description: "A value taken from the request or from a decoder is put in a variable and then run as an operating system command."
  },
  backtickInput: {
    id: "php.backtick_user_input",
    name: "Backtick shell command built from request input",
    severity: "critical",
    category: "exec",
    description: "Backticks in PHP run their contents as a shell command, and this one is built from what the visitor sends: remote command execution."
  },
  backtick: {
    id: "php.backtick_exec",
    name: "Shell command run with backticks",
    severity: "medium",
    category: "exec",
    description: "Backticks in PHP run their contents as a shell command. Site code rarely needs that, so it is worth knowing why this file does."
  }
};

function lineAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

/** Follow values through one text. Returns [{key, index}]. */
function follow(src, backticks) {
  // Every assignment to a plain variable, in order, with what it now holds.
  const assigned = new Map(); // name -> [{at, kind}]
  const note = (name, at, kind) => {
    if (!assigned.has(name)) assigned.set(name, []);
    assigned.get(name).push({ at, kind });
  };
  const holds = (name, before) => {
    const list = assigned.get(name);
    if (!list) return null;
    let found = null;
    for (const a of list) {
      if (a.at >= before) break;
      found = a;
    }
    return found;
  };
  const taintedIn = (expr, before) => {
    VARIABLE.lastIndex = 0;
    let v;
    while ((v = VARIABLE.exec(expr)) !== null) {
      const a = holds(v[1], before);
      if (a && a.kind) return a;
    }
    return null;
  };

  const events = [];
  let m;
  ASSIGN.lastIndex = 0;
  while ((m = ASSIGN.exec(src)) !== null) events.push({ at: m.index, name: m[1], append: m[2] === ".", expr: m[3] });
  FOREACH.lastIndex = 0;
  while ((m = FOREACH.exec(src)) !== null) events.push({ at: m.index, name: m[1], append: false, expr: "$_REQUEST" });
  events.sort((a, b) => a.at - b.at);

  for (const e of events) {
    let kind = null;
    if (!SANITIZER.test(e.expr)) {
      if (REQUEST.test(e.expr)) kind = "request";
      else if (DECODER.test(e.expr)) kind = "decoded";
      else {
        const from = taintedIn(e.expr, e.at);
        if (from) kind = from.kind;
      }
    }
    // Appending something harmless does not clean what was already there.
    if (kind || !e.append) note(e.name, e.at, kind);
  }
  if (!assigned.size) return [];

  const functions = [];
  FUNCTION.lastIndex = 0;
  while ((m = FUNCTION.exec(src)) !== null) functions.push(m.index);
  const sameFunction = (a, b) => !functions.some((f) => f > a && f < b);

  /** Does this argument text use a followed variable that is still in scope? */
  const carries = (args, at) => {
    if (SANITIZER.test(args)) return false;
    VARIABLE.lastIndex = 0;
    let v;
    while ((v = VARIABLE.exec(args)) !== null) {
      const a = holds(v[1], at);
      if (a && a.kind && sameFunction(a.at, at)) return true;
    }
    return false;
  };

  const hits = [];
  for (const [sink, key] of [[CODE_SINK, "eval"], [SHELL_SINK, "exec"]]) {
    sink.lastIndex = 0;
    while ((m = sink.exec(src)) !== null) {
      // A call made straight on request input is the signature rules' job.
      if (REQUEST.test(m[1])) continue;
      if (carries(m[1], m.index)) hits.push({ key, index: m.index });
    }
  }
  for (const [start, end] of backticks) {
    const inner = src.slice(start + 1, end - 1);
    if (!REQUEST.test(inner) && carries(inner, start)) hits.push({ key: "exec", index: start });
  }
  return hits;
}

/**
 * Run the follow-a-value checks on one PHP file.
 *
 * @param {string} text  the file as it is on disk
 * @param {{masked:string, sure:boolean, backticks:Array<[number,number]>}} php  from readPhp()
 */
export function runPhpFlow(text, php) {
  const hits = follow(php.masked, php.backticks);
  // Where the reading of the file is uncertain, follow the untouched text too.
  if (!php.sure) hits.push(...follow(text, php.backticks));

  for (const [start, end] of php.backticks) {
    const inner = text.slice(start + 1, end - 1);
    if (!inner.trim()) continue;
    hits.push({ key: REQUEST.test(inner) ? "backtickInput" : "backtick", index: start });
  }

  // One finding per check, at its first line, counting the rest.
  const byKey = new Map();
  for (const hit of hits.sort((a, b) => a.index - b.index)) {
    const line = lineAt(text, hit.index);
    if (!byKey.has(hit.key)) byKey.set(hit.key, new Set());
    byKey.get(hit.key).add(line);
  }
  // A backtick command that carries a followed value is already reported as that.
  if (byKey.has("exec") && byKey.has("backtick")) {
    for (const line of byKey.get("exec")) byKey.get("backtick").delete(line);
    if (!byKey.get("backtick").size) byKey.delete("backtick");
  }

  const findings = [];
  for (const [key, lineSet] of byKey) {
    const lines = [...lineSet].sort((a, b) => a - b);
    findings.push({
      ...FINDINGS[key],
      line: lines[0],
      matches: lines.length,
      lines,
      evidence: evidenceAt(text, lines[0]),
      references: ["https://owasp.org/www-community/attacks/Web_Shell"]
    });
  }
  return findings;
}
