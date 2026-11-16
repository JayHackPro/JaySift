/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

/**
 * A small reader for PHP source.
 *
 * The rules are regular expressions, and a regular expression cannot tell a
 * comment from code. That cuts both ways: a comment that mentions a dangerous
 * call used to be reported as one, and a comment slipped between a function
 * name and its bracket used to hide a real one. This reader walks a file the
 * way PHP does, far enough to know which characters are comments, which are
 * strings, and which backticks run a command, so the rules can look at the
 * code alone.
 *
 * It only ever blanks comments. Strings and inline HTML are left exactly as
 * they are. And it is careful about its own doubt: wherever PHP versions or
 * settings disagree on how a file reads (short open tags, a heredoc closed
 * the newer way, a string or comment that never ends), `sure` is false and
 * the caller keeps matching the untouched text as well, so a file built to
 * confuse this reader is still scanned in full.
 */

const OPEN_TAG = /<\?(?:php(?=\s|$)|=)/gi;
// A bare "<?" opens PHP only where short tags are on, and "<script
// language=php>" only before PHP 7. Either makes the reading uncertain.
const UNSURE_OPEN = /<\?(?!php(?:\s|$)|=|xml)|<script\b[^>]{0,80}\blanguage\s*=\s*["']?php/i;
const HEREDOC_OPEN = /<<<[ \t]*(["']?)([A-Za-z_\u0080-￿][\w\u0080-￿]*)\1\r?\n/y;

/** Replace every character but line breaks with a space, so line numbers hold. */
function blank(s) {
  return s.replace(/[^\n\r]/g, " ");
}

/**
 * Read PHP source.
 *
 * @param {string} text
 * @returns {{masked:string, sure:boolean, backticks:Array<[number,number]>, hasPhp:boolean}}
 *   masked     the text with comments blanked, same length and line breaks
 *   sure       false when the reading is uncertain and the raw text must be matched too
 *   backticks  [start, end) of every backtick command, ticks included
 *   hasPhp     whether the file opens PHP at all
 */
export function readPhp(text) {
  try {
    return read(text);
  } catch {
    // Nesting deep enough to exhaust the stack is itself a reason for doubt.
    return { masked: text, sure: false, backticks: [], hasPhp: true };
  }
}

function read(text) {
  const n = text.length;
  const comments = [];
  const backticks = [];
  let sure = !UNSURE_OPEN.test(text);
  let hasPhp = false;

  function lineComment(i) {
    let end = i + 1;
    while (end < n) {
      const c = text.charCodeAt(end);
      if (c === 10 || c === 13) break;
      if (c === 63 && text.charCodeAt(end + 1) === 62) break; // "?>" ends it too
      end++;
    }
    comments.push([i, end]);
    return end;
  }

  function blockComment(i) {
    const close = text.indexOf("*/", i + 2);
    if (close === -1) {
      sure = false;
      comments.push([i, n]);
      return n;
    }
    comments.push([i, close + 2]);
    return close + 2;
  }

  function singleQuoted(i) {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 92) i += 2;
      else if (c === 39) return i + 1;
      else i++;
    }
    sure = false;
    return n;
  }

  /** A double-quoted or backtick string, where {$...} and ${...} hold code. */
  function interpolated(i, quote) {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 92) i += 2;
      else if (c === quote) return i + 1;
      else if (c === 123 && text.charCodeAt(i + 1) === 36) i = code(i + 1, true);
      else if (c === 36 && text.charCodeAt(i + 1) === 123) i = code(i + 2, true);
      else i++;
    }
    sure = false;
    return n;
  }

  /** A heredoc or nowdoc starting at "<<<". Returns -1 if this is not one. */
  function heredoc(i) {
    HEREDOC_OPEN.lastIndex = i;
    const open = HEREDOC_OPEN.exec(text);
    if (!open) return -1;
    const nowdoc = open[1] === "'";
    const closing = new RegExp(`[ \\t]*${open[2]}(?![\\w\\u0080-\\uffff])`, "y");
    // Before PHP 7.3 the closing name had to start its line and end it, bar a
    // semicolon. A heredoc closed any other way reads differently on old PHP.
    const strict = new RegExp(`${open[2]};?[ \\t]*\\r?(?:\\n|$)`, "y");
    let j = i + open[0].length;
    while (j < n) {
      if (text.charCodeAt(j - 1) === 10) {
        closing.lastIndex = j;
        if (closing.test(text)) {
          strict.lastIndex = j;
          if (!strict.test(text)) sure = false;
          return closing.lastIndex;
        }
      }
      const c = text.charCodeAt(j);
      if (nowdoc) j++;
      else if (c === 92) j += 2;
      else if (c === 123 && text.charCodeAt(j + 1) === 36) j = code(j + 1, true);
      else if (c === 36 && text.charCodeAt(j + 1) === 123) j = code(j + 2, true);
      else j++;
    }
    sure = false;
    return n;
  }

  /**
   * PHP code from `i`. At the top level it runs to the closing tag. Nested
   * inside a string's {$...}, it runs to the matching brace.
   */
  function code(i, nested) {
    let depth = 0;
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 63 && text.charCodeAt(i + 1) === 62) {
        if (!nested) return i + 2;
        sure = false;
        i += 2;
      } else if (c === 47 && text.charCodeAt(i + 1) === 47) {
        i = lineComment(i);
      } else if (c === 47 && text.charCodeAt(i + 1) === 42) {
        i = blockComment(i);
      } else if (c === 35 && text.charCodeAt(i + 1) !== 91) {
        i = lineComment(i); // "#[" is an attribute, not a comment
      } else if (c === 39) {
        i = singleQuoted(i + 1);
      } else if (c === 34) {
        i = interpolated(i + 1, 34);
      } else if (c === 96) {
        const start = i;
        i = interpolated(i + 1, 96);
        backticks.push([start, i]);
      } else if (c === 60 && text.charCodeAt(i + 1) === 60 && text.charCodeAt(i + 2) === 60) {
        const end = heredoc(i);
        i = end === -1 ? i + 3 : end;
      } else if (nested && c === 123) {
        depth++;
        i++;
      } else if (nested && c === 125) {
        if (depth === 0) return i + 1;
        depth--;
        i++;
      } else {
        i++;
      }
    }
    if (nested) sure = false;
    return n;
  }

  let i = 0;
  while (i < n) {
    OPEN_TAG.lastIndex = i;
    const open = OPEN_TAG.exec(text);
    if (!open) break;
    hasPhp = true;
    i = code(open.index + open[0].length, false);
  }

  let masked = text;
  if (comments.length) {
    const parts = [];
    let last = 0;
    for (const [start, end] of comments) {
      parts.push(text.slice(last, start), blank(text.slice(start, end)));
      last = end;
    }
    parts.push(text.slice(last));
    masked = parts.join("");
  }
  return { masked, sure, backticks, hasPhp };
}

// "<?php" with nothing after it, or with only a die/exit guard, then the end
// of the block or of the file.
const EMPTY_BLOCK = /<\?php(?:\s+(?:die|exit)\s*(?:\(\s*(?:['"][^'"]*['"]|\d+)?\s*\))?)?\s*;?\s*(?:\?>|$)/gi;

/**
 * True when a file holds nothing that runs and nothing that is shown: only
 * comments, or a die/exit guard, such as the "Silence is golden" index.php
 * that WordPress and its plugins leave in folders to stop directory listings.
 */
export function holdsNoCode(text) {
  const { masked, sure } = readPhp(text);
  return (sure ? masked : text).replace(EMPTY_BLOCK, "").trim() === "";
}

/** True when the text opens with a PHP tag, allowing a byte order mark, blank space and a #! line. */
export function opensWithPhp(text) {
  return /^﻿?\s*(?:#![^\n]*\n\s*)?<\?php(?:\s|$)/i.test(text.slice(0, 512));
}
