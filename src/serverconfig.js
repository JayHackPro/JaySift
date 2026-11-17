/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

import { evidenceAt } from "./heuristics.js";

/**
 * Checks for server configuration files: .htaccess, .user.ini and php.ini.
 *
 * These files hold no code, so the code rules never looked at them, yet a few
 * lines in one can do as much as a webshell: run a picture as PHP, run a
 * hidden file before every page, or send visitors who arrive from a search
 * engine somewhere else. Each check reads directives line by line and skips
 * lines that are commented out.
 */

const MEDIA_EXT = /\.?\b(?:jpe?g|png|gif|ico|bmp|webp|svg|txt|pdf|css)\b/i;
const PHP_HANDLER = /php|cgi-script/i;
const SEARCH_VISITOR = /google|bing|yahoo|yandex|baidu|duckduckgo|aol\b|msn\b|ask\b|facebook|twitter|instagram/i;

// Firewall plugins legitimately load themselves this way.
const KNOWN_PREPEND = /(?:wordfence-waf|malcare-waf|aios-bootstrap)\.php$|ninjafirewall/i;
// A prepended file that is not a plain PHP file in an ordinary place.
const HIDDEN_TARGET = /^(?:https?|ftp|data|php|phar|zip|compress\.\w+):|\.(?:jpe?g|png|gif|ico|bmp|webp|svg|txt|log|css|js|dat|tmp|bak)$|\/(?:tmp|uploads?|cache|dev\/shm)\//i;

const FOUND = {
  handler: {
    id: "server.php_handler_on_media",
    name: "Images or text files set to run as PHP",
    severity: "critical",
    category: "backdoor",
    description: "This tells the web server to run pictures or text files as PHP, so an uploaded image can carry a working backdoor."
  },
  redirect: {
    id: "server.search_redirect",
    name: "Visitors from search engines sent elsewhere",
    severity: "high",
    category: "injection",
    description: "A rewrite that only applies to visitors arriving from a search engine or social site. The owner, who types the address, never sees it. This is how a hacked site sends its search traffic to another one."
  },
  prependHidden: {
    id: "server.auto_prepend_hidden",
    name: "A disguised file is run before every page",
    severity: "high",
    category: "backdoor",
    description: "auto_prepend_file makes PHP run a chosen file before every page. This one names a file that is not ordinary PHP in an ordinary place: an image, a temporary or uploads folder, or a remote address."
  },
  prepend: {
    id: "server.auto_prepend",
    name: "A file is run before every page",
    severity: "medium",
    category: "backdoor",
    description: "auto_prepend_file makes PHP run a chosen file before every page. Firewall plugins use it, and so do backdoors that want to survive a clean-up. Check that the file it names is one you installed."
  }
};

function unquote(value) {
  return value.trim().replace(/^["']|["']$/g, "").trim();
}

/**
 * @param {"htaccess"|"phpini"} kind
 * @param {string} text
 */
export function runServerConfigChecks(kind, text) {
  const hits = new Map(); // key -> [line numbers]
  const hit = (key, line) => {
    if (!hits.has(key)) hits.set(key, []);
    hits.get(key).push(line);
  };

  const comment = kind === "phpini" ? /^\s*[;#]/ : /^\s*#/;
  const lines = text.split("\n");
  let filesBlock = null; // the pattern of the <Files> block we are inside
  let searchCond = 0; // line of a pending RewriteCond on a search-engine referrer

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.trim() || comment.test(raw)) continue;
    const line = raw.trim();
    const n = i + 1;

    // auto_prepend_file / auto_append_file, in either file's spelling.
    const prepend = /^(?:php_(?:admin_)?value\s+)?auto_(?:prepend|append)_file\b\s*=?\s*(.*)$/i.exec(line);
    if (prepend) {
      const target = unquote(prepend[1].replace(/\s[;#].*$/, ""));
      if (target && !/^none$/i.test(target) && !KNOWN_PREPEND.test(target)) {
        hit(HIDDEN_TARGET.test(target) ? "prependHidden" : "prepend", n);
      }
      continue;
    }
    if (kind !== "htaccess") continue;

    const open = /^<Files(?:Match)?\b([^>]*)>/i.exec(line);
    if (open) {
      filesBlock = open[1];
      continue;
    }
    if (/^<\/Files/i.test(line)) {
      filesBlock = null;
      continue;
    }

    // AddType / AddHandler naming a PHP handler and a media extension.
    const add = /^(?:AddType|AddHandler)\s+(\S+)\s+(.+)$/i.exec(line);
    if (add && PHP_HANDLER.test(add[1]) && MEDIA_EXT.test(add[2].replace(/\s#.*$/, ""))) hit("handler", n);

    // A PHP handler forced inside a <Files> block that matches media names.
    const force = /^(?:SetHandler|ForceType|AddHandler|AddType)\s+(\S+)/i.exec(line);
    if (force && filesBlock !== null && PHP_HANDLER.test(force[1]) && MEDIA_EXT.test(filesBlock)) hit("handler", n);

    // RewriteCond on the referrer, naming search engines, not negated ...
    const cond = /^RewriteCond\s+%\{HTTP_REFERER\}\s+(\S+)/i.exec(line);
    if (cond) {
      if (!cond[1].startsWith("!") && SEARCH_VISITOR.test(cond[1])) searchCond = n;
      continue;
    }
    if (/^RewriteCond\b/i.test(line)) continue;
    // ... followed by a rule that really sends the visitor somewhere.
    const rule = /^RewriteRule\s+\S+\s+(\S+)/i.exec(line);
    if (rule) {
      if (searchCond && rule[1] !== "-") hit("redirect", searchCond);
      searchCond = 0;
    }
  }

  const findings = [];
  for (const [key, found] of hits) {
    findings.push({
      ...FOUND[key],
      line: found[0],
      matches: found.length,
      lines: found,
      evidence: evidenceAt(text, found[0]),
      references: ["https://httpd.apache.org/docs/current/howto/htaccess.html"]
    });
  }
  return findings;
}
