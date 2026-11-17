/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

import { evidenceAt } from "./heuristics.js";

/**
 * Calls made by name.
 *
 * PHP will call a function whose name is only a string. That lets a backdoor
 * run a command without the command function's name ever standing in front
 * of a bracket, which is where the signature rules look for it:
 *
 *     $f = 'sys' . 'tem';                          a name joined from pieces
 *     $f($_GET['c']);                              and called through a variable
 *
 *     array_filter(array($_GET['c']), 'system');   or handed over as a callback
 *
 * These checks read the code as words rather than as text. They work out
 * which variables hold a fixed string, joining the pieces the way PHP would,
 * and report when a string that names a command or code function is called,
 * or passed as a callback, on something the visitor sent.
 *
 * Nothing is ever run. The file is only read, split into names, strings and
 * punctuation, and compared.
 *
 * What keeps this honest:
 *   - Text inside a comment or inside a string is never read as code.
 *   - A variable is not followed from one function into another, except
 *     through `use` and `global`, which say so themselves.
 *   - A later assignment replaces an earlier one. An assignment inside a
 *     branch only adds a possibility, because the branch may not run.
 *   - Only request input counts, and not once it has passed through an
 *     escaping or validating function.
 *
 * It is still name matching, not an analysis of the whole program, so its
 * findings are high rather than critical.
 */

const REQUEST = /\$_(?:GET|POST|REQUEST|COOKIE)\b|php:\/\/input|\$HTTP_RAW_POST_DATA\b|\$_SERVER\s*\[\s*["']HTTP_/i;

const REQUEST_VARS = new Set(["_GET", "_POST", "_REQUEST", "_COOKIE", "HTTP_RAW_POST_DATA"]);

// Functions that run a command, or run a string as code, when called by name.
const DANGEROUS = new Set([
  "system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec",
  "assert", "create_function"
]);

// Functions that call another function back, and where in their arguments
// the callback sits. Every other argument is what the callback is called on.
const TAKERS = new Map([
  ["call_user_func", 0],
  ["call_user_func_array", 0],
  ["forward_static_call", 0],
  ["forward_static_call_array", 0],
  ["array_map", 0],
  ["register_shutdown_function", 0],
  ["register_tick_function", 0],
  ["array_filter", 1],
  ["array_walk", 1],
  ["array_walk_recursive", 1],
  ["array_reduce", 1],
  ["usort", 1],
  ["uasort", 1],
  ["uksort", 1]
]);

// The same list flow.js uses: a value that went through one of these is not followed.
const SANITIZERS = new Set([
  "escapeshellarg", "escapeshellcmd", "intval", "floatval", "absint", "filter_var", "filter_input",
  "preg_quote", "basename", "md5", "sha1", "hash", "crc32", "strlen", "count", "isset", "empty",
  "in_array", "array_key_exists", "wp_verify_nonce"
]);
const isSanitizer = (name) =>
  SANITIZERS.has(name) || name.startsWith("sanitize_") || name.startsWith("esc_") || name.startsWith("is_");
const CASTS = new Set(["int", "integer", "float", "double", "bool", "boolean"]);

const CONTROL = new Set(["if", "elseif", "while", "for", "foreach", "switch"]);
const CLASSLIKE = new Set(["class", "interface", "trait", "enum"]);
const END_ALT = new Set(["endif", "endwhile", "endfor", "endforeach", "endswitch"]);
// Words after which a round bracket opens a value rather than a call's arguments.
const BEFORE_VALUE = new Set(["return", "echo", "print", "and", "or", "xor", "else", "do", "case", "yield", "throw"]);

const FINDINGS = {
  call: {
    id: "php.call_by_name",
    name: "Command or code function called by name on request input",
    severity: "high",
    category: "exec",
    description:
      "A function that runs a command or runs text as code is called through a string that holds its name, and it is given what the visitor sent. The name may be joined from pieces so that it never appears whole. Site code has no reason to call these functions this way."
  },
  callback: {
    id: "php.callback_by_name",
    name: "Command or code function passed by name as a callback on request input",
    severity: "high",
    category: "exec",
    description:
      "A function that runs a command or runs text as code is handed, as a name in a string, to a function that calls it back, and what it is called on comes from the visitor. It is a command call with the function's name kept away from the bracket."
  }
};

// Token kinds.
const VAR = 1, STR = 2, ID = 3, NUM = 4, LP = 5, RP = 6, LB = 7, RB = 8, LC = 9, RC = 10, COMMA = 11,
  SEMI = 12, DOT = 13, ASSIGN = 14, APPEND = 15, OPASSIGN = 16, ARROW = 17, STATIC = 18, DOLLAR = 19,
  COLON = 20, OTHER = 21;

const SINGLE = { 40: LP, 41: RP, 91: LB, 93: RB, 123: LC, 125: RC, 44: COMMA, 59: SEMI, 46: DOT, 61: ASSIGN, 36: DOLLAR, 58: COLON };
const THREE = { "?->": ARROW, "===": OTHER, "!==": OTHER, "<=>": OTHER, "...": OTHER, "??=": OPASSIGN, "**=": OPASSIGN, "<<=": OPASSIGN, ">>=": OPASSIGN };
const TWO = {
  "->": ARROW, "::": STATIC, "=>": OTHER, "==": OTHER, "!=": OTHER, "<>": OTHER, "<=": OTHER, ">=": OTHER,
  ".=": APPEND, "+=": OPASSIGN, "-=": OPASSIGN, "*=": OPASSIGN, "/=": OPASSIGN, "%=": OPASSIGN, "&=": OPASSIGN,
  "|=": OPASSIGN, "^=": OPASSIGN, "&&": OTHER, "||": OTHER, "??": OTHER, "++": OTHER, "--": OTHER, "<<": OTHER,
  ">>": OTHER, "**": OTHER, "?>": SEMI // a closing tag ends the statement, as PHP reads it
};

const isNameStart = (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c >= 128;
const isNamePart = (c) => isNameStart(c) || (c >= 48 && c <= 57);
const isSpace = (c) => c === 32 || c === 10 || c === 13 || c === 9 || c === 11 || c === 12;

const NAIVE_HEREDOC = /<<<[ \t]*(["']?)([A-Za-z_]\w*)\1\r?\n/y;

/**
 * Split code into tokens: kinds and positions only, as three flat lists.
 *
 * @param {string} src                       the text
 * @param {Array<[number,number]>} regions   the stretches of it that are code
 * @param {Map<number,number>|null} ends     where each string ends, from readPhp(); null to find them here
 */
function lex(src, regions, ends) {
  // A token is at least one character, so the length of the code bounds their number.
  let room = 1;
  for (const [from, to] of regions) room += Math.max(0, to - from);
  const T = new Uint8Array(room);
  const S = new Int32Array(room);
  const E = new Int32Array(room);
  let n = 0;
  const push = (t, s, e) => {
    T[n] = t;
    S[n] = s;
    E[n] = e;
    n++;
  };

  for (const [from, to] of regions) {
    const lineEnd = (i) => {
      while (i < to) {
        const c = src.charCodeAt(i);
        if (c === 10 || c === 13) break;
        if (c === 63 && src.charCodeAt(i + 1) === 62) break;
        i++;
      }
      return i;
    };
    const quoteEnd = (i, quote) => {
      if (ends && ends.has(i)) return Math.min(ends.get(i), to);
      let j = i + 1;
      while (j < to) {
        const c = src.charCodeAt(j);
        if (c === 92) j += 2;
        else if (c === quote) return j + 1;
        else j++;
      }
      return to;
    };
    const heredocEnd = (i) => {
      if (ends && ends.has(i)) return Math.min(ends.get(i), to);
      NAIVE_HEREDOC.lastIndex = i;
      const open = NAIVE_HEREDOC.exec(src);
      if (!open) return -1;
      const close = new RegExp(`\\n[ \\t]*${open[2]}\\b`, "g");
      close.lastIndex = i + open[0].length - 1;
      return close.exec(src) ? Math.min(close.lastIndex, to) : to;
    };

    let i = from;
    while (i < to) {
      const c = src.charCodeAt(i);
      if (isSpace(c)) {
        i++;
      } else if (c === 47 && src.charCodeAt(i + 1) === 47) {
        i = lineEnd(i);
      } else if (c === 47 && src.charCodeAt(i + 1) === 42) {
        const close = src.indexOf("*/", i + 2);
        i = close === -1 || close + 2 > to ? to : close + 2;
      } else if (c === 35 && src.charCodeAt(i + 1) !== 91) {
        i = lineEnd(i);
      } else if (c === 39 || c === 34 || c === 96) {
        const end = quoteEnd(i, c);
        push(STR, i, end);
        i = end;
      } else if (c === 60 && src.charCodeAt(i + 1) === 60 && src.charCodeAt(i + 2) === 60 && heredocEnd(i) !== -1) {
        const end = heredocEnd(i);
        push(STR, i, end);
        i = end;
      } else if (c === 36 && isNameStart(src.charCodeAt(i + 1))) {
        let j = i + 2;
        while (j < to && isNamePart(src.charCodeAt(j))) j++;
        push(VAR, i, j);
        i = j;
      } else if (isNameStart(c) || (c === 92 && isNameStart(src.charCodeAt(i + 1)))) {
        let j = i + 1;
        while (j < to && (isNamePart(src.charCodeAt(j)) || src.charCodeAt(j) === 92)) j++;
        push(ID, i, j);
        i = j;
      } else if (c >= 48 && c <= 57) {
        let j = i + 1;
        while (j < to && (isNamePart(src.charCodeAt(j)) || src.charCodeAt(j) === 46)) j++;
        push(NUM, i, j);
        i = j;
      } else {
        const three = THREE[src.substr(i, 3)];
        const two = three ? 0 : TWO[src.substr(i, 2)];
        if (three) {
          push(three, i, i + 3);
          i += 3;
        } else if (two) {
          push(two, i, i + 2);
          i += 2;
        } else {
          push(SINGLE[c] || OTHER, i, i + 1);
          i++;
        }
      }
    }
  }
  return { T, S, E, n };
}

const SIMPLE_ESCAPES = { n: "\n", t: "\t", r: "\r", v: "\v", e: "\x1b", f: "\f", "\\": "\\", $: "$", '"': '"' };

/** The text a double-quoted string stands for, or null if it holds a variable. */
function decodeDouble(inner) {
  let out = "";
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === "\\" && i + 1 < inner.length) {
      const next = inner[i + 1];
      if (next === "x") {
        const hex = /^[0-9A-Fa-f]{1,2}/.exec(inner.slice(i + 2, i + 4));
        if (hex) {
          out += String.fromCharCode(parseInt(hex[0], 16));
          i += 1 + hex[0].length;
          continue;
        }
      } else if (next >= "0" && next <= "7") {
        const oct = /^[0-7]{1,3}/.exec(inner.slice(i + 1, i + 4));
        out += String.fromCharCode(parseInt(oct[0], 8) & 255);
        i += oct[0].length;
        continue;
      } else if (next === "u" && inner[i + 2] === "{") {
        const end = inner.indexOf("}", i + 3);
        const point = end === -1 ? NaN : parseInt(inner.slice(i + 3, end), 16);
        if (Number.isFinite(point) && point <= 0x10ffff) {
          out += String.fromCodePoint(point);
          i = end;
          continue;
        }
      } else if (Object.hasOwn(SIMPLE_ESCAPES, next)) {
        out += SIMPLE_ESCAPES[next];
        i++;
        continue;
      }
      out += ch;
      continue;
    }
    if (ch === "$" && /[A-Za-z_{\u0080-\uffff]/.test(inner[i + 1] || "")) return null;
    if (ch === "{" && inner[i + 1] === "$") return null;
    out += ch;
  }
  return out;
}

const MAX_NAME = 64; // no function name worth finding is longer
const MAX_VALUES = 8; // how many different strings one variable may be seen to hold
const SPAN = 600; // how far to look for a closing bracket
const HEADER_SPAN = 4000;
// Looking for closing brackets is the one step that could be made slow on
// purpose, by a file of brackets that never close. Once this much looking has
// been spent, each further search looks only a short way, which is still far
// enough to read an ordinary call and keeps the whole file to a bounded cost.
const WORK = 40_000_000;
const TIGHT = 64;

function cross(a, b) {
  const out = [];
  for (const x of a) {
    for (const y of b) {
      const joined = x + y;
      if (joined.length <= MAX_NAME && !out.includes(joined)) out.push(joined);
      if (out.length >= MAX_VALUES) return out;
    }
  }
  return out.length ? out : null;
}

/** The command or code function a string names, or null. */
function dangerous(values) {
  if (!values) return null;
  for (const value of values) {
    let name = value.toLowerCase();
    if (name.charCodeAt(0) === 92) name = name.slice(1);
    if (DANGEROUS.has(name)) return name;
  }
  return null;
}

/** Read one stretch of tokens. Returns [{key, index}]. */
function analyze(src, regions, ends) {
  const { T, S, E, n } = lex(src, regions, ends);
  const hits = [];
  if (!n) return hits;

  const id = (k) => {
    const s = src.slice(S[k], E[k]).toLowerCase();
    return s.charCodeAt(0) === 92 ? s.slice(1) : s;
  };
  const isId = (k, name) => T[k] === ID && id(k) === name;
  const varName = (k) => src.slice(S[k] + 1, E[k]);

  const strValue = (k) => {
    if (E[k] - S[k] > 4 * MAX_NAME) return null;
    const quote = src.charCodeAt(S[k]);
    const inner = src.slice(S[k] + 1, E[k] - 1);
    if (quote === 39) return inner.replace(/\\([\\'])/g, "$1");
    if (quote === 34) return decodeDouble(inner);
    return null;
  };

  /** The bracket that closes the one at k, looking no further than `stop`. */
  let budget = WORK;
  const close = (k, stop) => {
    if (budget <= 0) stop = Math.min(stop, k + TIGHT);
    let depth = 0;
    for (let j = k; j < stop; j++) {
      const t = T[j];
      if (t === LP || t === LB || t === LC) depth++;
      else if (t === RP || t === RB || t === RC) {
        depth--;
        if (depth === 0) {
          budget -= j - k;
          return j;
        }
      }
    }
    budget -= stop - k;
    return -1;
  };
  const closeNear = (k, span = SPAN) => close(k, Math.min(n, k + span));

  /** [lo, hi) cut at its top-level commas. */
  const split = (lo, hi) => {
    const parts = [];
    let depth = 0;
    let start = lo;
    for (let j = lo; j < hi; j++) {
      const t = T[j];
      if (t === LP || t === LB || t === LC) depth++;
      else if (t === RP || t === RB || t === RC) depth--;
      else if (t === COMMA && depth === 0) {
        parts.push([start, j]);
        start = j + 1;
      }
    }
    parts.push([start, hi]);
    return parts;
  };

  // ----- what each variable holds, per function

  const newScope = () => ({ vars: new Map(), path: "0", paths: [], seq: 0 });
  const root = newScope();
  const scopes = [root];
  let scope = root;
  const braces = []; // "block", "class", "fn" or "alt", innermost last
  const opens = []; // where each of those opened, or -1 for one written with a colon
  let closedAt = -1; // the last closing brace, and the brace it closed
  let closedFrom = -1;
  let conditional = false; // inside a statement that hangs off an if or a loop without braces

  const assign = (name, vals, tainted) => {
    let list = scope.vars.get(name);
    if (!list) scope.vars.set(name, (list = []));
    if (!conditional) {
      // This assignment certainly replaces what was set here or further in.
      const here = scope.path;
      for (let i = list.length - 1; i >= 0; i--) {
        const p = list[i].path;
        if (p === here || p.startsWith(here + "/")) list.splice(i, 1);
      }
    }
    list.push({ path: scope.path, vals, tainted });
    if (list.length > 16) list.shift();
  };
  const constVals = (name) => {
    const list = scope.vars.get(name);
    if (!list) return null;
    const out = [];
    for (const entry of list) {
      if (!entry.vals) continue;
      for (const v of entry.vals) if (!out.includes(v) && out.length < MAX_VALUES) out.push(v);
    }
    return out.length ? out : null;
  };
  const isTainted = (name) => {
    const list = scope.vars.get(name);
    return !!list && list.some((entry) => entry.tainted);
  };

  const openBlock = (kind, at = -1) => {
    braces.push(kind);
    opens.push(at);
    scope.paths.push(scope.path);
    scope.path += "/" + ++scope.seq;
  };
  const closeBlock = () => {
    const kind = braces.pop();
    closedFrom = opens.length ? opens.pop() : -1;
    if (kind === "fn") {
      if (scopes.length > 1) scopes.pop();
      scope = scopes[scopes.length - 1];
    } else if (kind && scope.paths.length) {
      scope.path = scope.paths.pop();
    }
    return kind;
  };

  // ----- reading values

  /** The fixed string(s) the tokens in [lo, hi) stand for, or null. */
  const constOf = (lo, hi) => {
    if (hi <= lo || hi - lo > 200) return null;
    let p = lo;
    const term = () => {
      if (p >= hi) return null;
      const t = T[p];
      if (t === STR) {
        const v = strValue(p++);
        return v === null || v.length > MAX_NAME ? null : [v];
      }
      if (t === VAR) {
        const next = p + 1 < hi ? T[p + 1] : 0;
        if (next === LB || next === LC || next === LP || next === ARROW || next === STATIC) return null;
        if (p > 0 && (T[p - 1] === ARROW || T[p - 1] === STATIC || T[p - 1] === DOLLAR)) return null;
        return constVals(varName(p++));
      }
      if (t === LP) {
        const end = close(p, hi);
        if (end === -1) return null;
        const inner = constOf(p + 1, end);
        p = end + 1;
        return inner;
      }
      if (t === ID && p + 1 < hi && T[p + 1] === LP) {
        const name = id(p);
        const end = close(p + 1, hi);
        if (end === -1) return null;
        const from = p + 2;
        p = end + 1;
        if (name === "chr") return chrOf(from, end);
        if (name === "implode" || name === "join") return joinOf(from, end);
      }
      return null;
    };
    let acc = term();
    while (acc && p < hi) {
      if (T[p] !== DOT) return null;
      p++;
      const next = term();
      acc = next ? cross(acc, next) : null;
    }
    return acc;
  };
  const chrOf = (lo, hi) => {
    if (hi - lo !== 1 || T[lo] !== NUM) return null;
    const text = src.slice(S[lo], E[lo]);
    const value = /^0x/i.test(text) ? parseInt(text, 16) : /^0[0-7]+$/.test(text) ? parseInt(text, 8) : /^\d+$/.test(text) ? parseInt(text, 10) : NaN;
    return Number.isFinite(value) ? [String.fromCharCode(value & 255)] : null;
  };
  const joinOf = (lo, hi) => {
    const parts = split(lo, hi);
    if (parts.length > 2) return null;
    const glue = parts.length === 2 ? constOf(parts[0][0], parts[0][1]) : [""];
    if (!glue || glue.length !== 1) return null;
    let [a, b] = parts[parts.length - 1];
    if (isId(a, "array") && T[a + 1] === LP && close(a + 1, b) === b - 1) a += 2;
    else if (T[a] === LB && close(a, b) === b - 1) a += 1;
    else return null;
    const pieces = [];
    for (const [x, y] of split(a, b - 1)) {
      if (x === y) continue; // a trailing comma
      const piece = constOf(x, y);
      if (!piece || piece.length !== 1) return null;
      pieces.push(piece[0]);
    }
    const joined = pieces.join(glue[0]);
    return joined.length <= MAX_NAME ? [joined] : null;
  };

  /** Do the tokens in [lo, hi) carry something the visitor sent? */
  const fromRequest = (lo, hi) => {
    for (let j = lo; j < hi; j++) {
      const t = T[j];
      if (t === LP && j + 2 < hi && T[j + 1] === ID && T[j + 2] === RP && CASTS.has(id(j + 1))) return false;
      if (t === ID && T[j + 1] === LP && isSanitizer(id(j))) {
        const end = close(j + 1, hi);
        if (end === -1) return false;
        j = end;
      } else if (t === VAR) {
        const name = varName(j);
        if (REQUEST_VARS.has(name)) return true;
        if (name === "_SERVER" && T[j + 1] === LB && T[j + 2] === STR && /^["']HTTP_/i.test(src.substr(S[j + 2], 6))) return true;
        if (j > 0 && (T[j - 1] === ARROW || T[j - 1] === STATIC)) continue;
        if (isTainted(name)) return true;
      } else if (t === STR && E[j] - S[j] <= MAX_NAME && /php:\/\/input/i.test(src.slice(S[j], E[j]))) {
        return true;
      }
    }
    return false;
  };

  /** Where the expression that starts at lo ends. */
  const exprEnd = (lo) => {
    let depth = 0;
    const stop = Math.min(n, lo + SPAN);
    for (let j = lo; j < stop; j++) {
      const t = T[j];
      if (t === LP || t === LB || t === LC) depth++;
      else if (t === RP || t === RB || t === RC) {
        if (depth === 0) return j;
        depth--;
      } else if ((t === SEMI || t === COMMA) && depth === 0) return j;
    }
    return stop;
  };

  // ----- one pass, in order

  const afterHeader = new Set(); // the closing bracket of each if (...), while (...) and so on
  const groups = []; // open round brackets
  let pendingClass = false;

  let k = 0;
  while (k < n) {
    const t = T[k];
    const prev = k > 0 ? T[k - 1] : 0;

    // The first token after a control header says how its body is written.
    if (k > 0 && afterHeader.has(k - 1)) {
      if (t === COLON) {
        openBlock("alt");
        k++;
        continue;
      }
      if (t !== LC && t !== SEMI) conditional = true;
    }

    if (t === LC) {
      if (pendingClass && !groups.length) {
        openBlock("class", k);
        pendingClass = false;
      } else openBlock("block", k);
    } else if (t === RC) {
      while (braces.length && braces[braces.length - 1] === "alt") closeBlock();
      closeBlock();
      closedAt = k;
    } else if (t === SEMI) {
      if (!groups.length) {
        conditional = false;
        pendingClass = false;
      }
    } else if (t === LP) {
      groups.push(k);
    } else if (t === RP) {
      const open = groups.pop();
      // ('sys' . 'tem')($x): a bracketed string, called.
      if (open !== undefined && T[k + 1] === LP && k - open <= 60) {
        const before = open > 0 ? T[open - 1] : 0;
        // After a word, a variable or a closing bracket the brackets hold a
        // call's arguments. After a brace they do too when the brace closed a
        // name, as in $object->{$name}(...), and not when it closed a block.
        let grouping = before !== VAR && before !== RP && before !== RB && before !== STR;
        if (before === ID) grouping = BEFORE_VALUE.has(id(open - 1));
        else if (before === RC) {
          const opener = closedAt === open - 1 && closedFrom > 0 ? T[closedFrom - 1] : 0;
          grouping = opener !== ARROW && opener !== STATIC && opener !== DOLLAR;
        }
        if (grouping) {
          const end = closeNear(k + 1);
          if (end !== -1 && dangerous(constOf(open + 1, k)) && fromRequest(k + 2, end)) hits.push({ key: "call", index: S[open] });
        }
      }
    } else if (t === STR) {
      // 'system'($x): a string, called.
      if (T[k + 1] === LP && dangerous([strValue(k) || ""])) {
        const end = closeNear(k + 1);
        if (end !== -1 && fromRequest(k + 2, end)) hits.push({ key: "call", index: S[k] });
      }
    } else if (t === VAR) {
      const next = T[k + 1];
      const plain = prev !== ARROW && prev !== STATIC && prev !== DOLLAR;
      if (plain && (next === ASSIGN || next === APPEND || next === OPASSIGN)) {
        if (braces[braces.length - 1] !== "class") {
          const name = varName(k);
          const lo = k + 2;
          const hi = exprEnd(lo);
          if (next === OPASSIGN) assign(name, null, false);
          else if (next === APPEND) {
            const had = constVals(name);
            const more = constOf(lo, hi);
            assign(name, had && more ? cross(had, more) : null, isTainted(name) || fromRequest(lo, hi));
          } else assign(name, constOf(lo, hi), fromRequest(lo, hi));
        }
        k += 2;
        continue;
      }
      // $a[] = $_GET['c'] or $a['k'] = ...: the array now carries the request value.
      if (plain && next === LB) {
        const end = close(k + 1, Math.min(n, k + 40));
        if (end !== -1 && (T[end + 1] === ASSIGN || T[end + 1] === APPEND) && fromRequest(end + 2, exprEnd(end + 2))) {
          const name = varName(k);
          if (!scope.vars.has(name)) scope.vars.set(name, []);
          scope.vars.get(name).push({ path: scope.path, vals: null, tainted: true });
        }
      }
      // $f($x): a variable, called. Not a method, not a class being made.
      if (plain && next === LP && !(prev === ID && (id(k - 1) === "new" || id(k - 1) === "function" || id(k - 1) === "fn"))) {
        if (dangerous(constVals(varName(k)))) {
          const end = closeNear(k + 1);
          if (end !== -1 && fromRequest(k + 2, end)) hits.push({ key: "call", index: S[k] });
        }
      }
    } else if (t === ID && prev !== ARROW && prev !== STATIC) {
      const name = id(k);
      const next = T[k + 1];

      if (name === "function") {
        let j = k + 1;
        if (T[j] === OTHER && src.charCodeAt(S[j]) === 38) j++;
        if (T[j] === ID) j++;
        const params = T[j] === LP ? closeNear(j, HEADER_SPAN) : -1;
        if (params !== -1) {
          j = params + 1;
          const uses = [];
          if (isId(j, "use") && T[j + 1] === LP) {
            const end = closeNear(j + 1);
            if (end !== -1) {
              for (let m = j + 2; m < end; m++) if (T[m] === VAR) uses.push(varName(m));
              j = end + 1;
            }
          }
          if (T[j] === COLON) {
            j++;
            const stop = Math.min(n, j + 24);
            while (j < stop && T[j] !== LC && T[j] !== SEMI) j++;
          }
          if (T[j] === LC) {
            const child = newScope();
            for (const used of uses) {
              const vals = constVals(used);
              const tainted = isTainted(used);
              if (vals || tainted) child.vars.set(used, [{ path: "0", vals, tainted }]);
            }
            braces.push("fn");
            opens.push(j);
            scopes.push(child);
            scope = child;
            k = j + 1;
          } else k = j;
          continue;
        }
      } else if (name === "fn" && next === LP) {
        // An arrow function reads its surroundings, so only its parameters are stepped over.
        const end = closeNear(k + 1, HEADER_SPAN);
        if (end !== -1) {
          k = end + 1;
          continue;
        }
      } else if (name === "global") {
        for (let j = k + 1; j < n && T[j] !== SEMI && j < k + 40; j++) {
          if (T[j] !== VAR) continue;
          const list = root.vars.get(varName(j));
          if (list && scope !== root) scope.vars.set(varName(j), list.map((entry) => ({ ...entry, path: scope.path })));
        }
      } else if (CLASSLIKE.has(name)) {
        pendingClass = true;
      } else if (CONTROL.has(name) && next === LP) {
        // elseif (...): closes the branch before it and opens its own.
        if (name === "elseif" && braces[braces.length - 1] === "alt") closeBlock();
        const end = closeNear(k + 1, HEADER_SPAN);
        if (end !== -1) {
          afterHeader.add(end);
          if (name === "foreach") {
            let as = -1;
            let depth = 0;
            for (let j = k + 2; j < end; j++) {
              if (T[j] === LP || T[j] === LB || T[j] === LC) depth++;
              else if (T[j] === RP || T[j] === RB || T[j] === RC) depth--;
              else if (depth === 0 && isId(j, "as")) {
                as = j;
                break;
              }
            }
            if (as !== -1) {
              const tainted = fromRequest(k + 2, as);
              for (let j = as + 1; j < end; j++) if (T[j] === VAR) assign(varName(j), null, tainted);
            }
          }
        }
      } else if (name === "else") {
        if (next === COLON) {
          if (braces[braces.length - 1] === "alt") closeBlock();
          openBlock("alt");
          k += 2;
          continue;
        }
        if (next !== LC && !isId(k + 1, "if")) conditional = true;
      } else if (END_ALT.has(name)) {
        if (braces[braces.length - 1] === "alt") closeBlock();
      } else if (next === LP && !(prev === ID && (id(k - 1) === "function" || id(k - 1) === "new"))) {
        // Not a function being declared under one of these names, nor a class being made.
        const end = TAKERS.has(name) || name === "filter_var" ? closeNear(k + 1) : -1;
        if (end !== -1 && TAKERS.has(name)) {
          const args = split(k + 2, end);
          const at = TAKERS.get(name);
          if (args.length > at && dangerous(constOf(args[at][0], args[at][1]))) {
            if (args.some(([a, b], i) => i !== at && fromRequest(a, b))) hits.push({ key: "callback", index: S[k] });
          }
        } else if (end !== -1 && name === "filter_var") {
          // filter_var($x, FILTER_CALLBACK, array('options' => 'system'))
          const args = split(k + 2, end);
          if (args.length >= 3 && args[1][1] - args[1][0] === 1 && isId(args[1][0], "filter_callback")) {
            let named = false;
            for (let j = args[2][0]; j < args[2][1] && !named; j++) {
              if (T[j] === STR) named = !!dangerous([strValue(j) || ""]);
              else if (T[j] === VAR) named = !!dangerous(constVals(varName(j)));
            }
            if (named && fromRequest(args[0][0], args[0][1])) hits.push({ key: "callback", index: S[k] });
          }
        }
      }
    }
    k++;
  }
  return hits;
}

/** Every stretch between an open tag of any kind and its closing tag. */
function looseRegions(text) {
  const regions = [];
  const open = /<\?(?:php\b|=)?/gi;
  let m;
  while ((m = open.exec(text)) !== null) {
    const start = m.index + m[0].length;
    const end = text.indexOf("?>", start);
    regions.push([start, end === -1 ? text.length : end + 2]);
    if (end === -1) break;
    open.lastIndex = end + 2;
  }
  return regions.length ? regions : [[0, text.length]];
}

function lineAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

/**
 * Run the calls-by-name checks on one PHP file.
 *
 * @param {string} text  the file as it is on disk
 * @param {{masked:string, sure:boolean, strings:Array<[number,number]>, blocks:Array<[number,number]>}} php  from readPhp()
 */
export function runPhpCalls(text, php) {
  // Every finding here needs request input, so a file without any is done.
  if (!REQUEST.test(text)) return [];

  let hits = [];
  try {
    hits = analyze(php.masked, php.blocks || [], new Map(php.strings || []));
    // Where the reading of the file is uncertain, read it the loose way too:
    // everything between any kind of open tag and its close.
    if (!php.sure) hits.push(...analyze(text, looseRegions(text), null));
  } catch {
    return [];
  }

  const byKey = new Map();
  for (const hit of hits.sort((a, b) => a.index - b.index)) {
    if (!byKey.has(hit.key)) byKey.set(hit.key, new Set());
    byKey.get(hit.key).add(lineAt(text, hit.index));
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
