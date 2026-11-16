/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

import path from "node:path";
import { color, severityColor } from "./colors.js";
import { worstSeverity } from "./scanner.js";
import { countSiteRoles, SITE_ROLES } from "./site.js";
import { atLeast, countVerdicts, SERIOUS_FROM } from "./severity.js";

const GLYPH = {
  critical: "✕", // x
  high: "▲", // triangle
  medium: "◆", // diamond
  low: "○" // circle
};

function human(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function seconds(ms) {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** The JaySift header line, brand green on the terminal. */
export function banner() {
  const mark = color.brand(color.bold("JaySift"));
  return `${color.brand("▓▓")} ${mark} ${color.dim("malware scanner by JayHackPro")}`;
}

const files = (n) => `${n} file${n === 1 ? "" : "s"}`;

/**
 * A one-line summary suitable for logs. A file is only called likely
 * malicious on a critical or high finding; medium and low are things to look
 * at, and the line says which of the two a scan found.
 */
export function summaryLine(result) {
  const worst = worstSeverity(result);
  const scanned = result.stats.scanned;
  if (!worst) return `clean: ${scanned} files scanned, nothing found`;
  const { likelyMalicious, review } = countVerdicts(result.flagged || result.infected);
  if (!likelyMalicious) return `to review: ${files(review)} worth a look of ${scanned} scanned, none likely malicious`;
  return `${worst} risk: ${likelyMalicious} likely malicious${review ? `, ${review} to review` : ""} of ${scanned} scanned`;
}

/**
 * Format a full human report as a string.
 *
 * @param {object} result   from scan()
 * @param {object} [opts]
 * @param {boolean} [opts.verbose]  include rule ids and references
 * @param {object} [opts.quarantine]  what quarantineFiles() returned, if files were just moved
 */
export function formatHuman(result, opts = {}) {
  const out = [];
  const records = result.flagged || result.infected;
  const q = opts.quarantine && !opts.quarantine.dryRun ? opts.quarantine : null;
  const movedPaths = new Set(q ? q.moved.map((m) => m.path) : []);
  out.push("");
  if (opts.header !== false) {
    out.push("  " + banner());
    out.push("");
  }
  out.push(
    "  " +
      color.dim(
        `Scanned ${result.stats.scanned} files (${human(result.stats.bytes)}) in ${seconds(result.durationMs)}`
      )
  );

  if (result.stats.skippedLarge || result.stats.unreadable) {
    const notes = [];
    if (result.stats.skippedLarge) notes.push(`${result.stats.skippedLarge} skipped for size`);
    if (result.stats.unreadable) notes.push(`${result.stats.unreadable} unreadable`);
    out.push("  " + color.dim(notes.join(", ")));
  }
  for (const site of result.sites || []) {
    const v = site.version ? `WordPress ${site.version}` : "WordPress (version not read)";
    out.push("  " + color.dim(`${v} at ${site.root}`));
  }
  if (result.stats.skippedDirs) {
    const names = (result.skippedDirNames || []).join(", ");
    const plural = result.stats.skippedDirs === 1 ? "folder" : "folders";
    const include = (result.skippedDirNames || []).join(",") || "all";
    out.push("  " + color.dim(`Skipped ${result.stats.skippedDirs} ${plural} by name (${names}). Scan them too with --include ${include}`));
  }
  out.push("");

  if (!records.length) {
    out.push("  " + color.green(color.bold("✔ No malware found.")));
    out.push("  " + color.dim("Nothing in the files scanned matched a known technique, heuristic, or bad hash."));
    out.push("");
    return out.join("\n");
  }

  for (const record of records) {
    const worst = record.findings[0].severity;
    const paint = severityColor(worst);
    const verb = !q ? "" : color.dim(movedPaths.has(path.resolve(record.path)) ? " (quarantined)" : " (left in place)");
    const site = record.site ? color.dim(` [wordpress ${record.site.role}]`) : "";
    out.push("  " + paint(color.bold(worst.toUpperCase().padEnd(9))) + color.bold(record.path) + site + verb);

    for (const f of record.findings) {
      const g = severityColor(f.severity)(GLYPH[f.severity] || "•");
      const where = f.line ? color.dim(`:${f.line}`) : "";
      const count = f.matches && f.matches > 1 ? color.dim(` (${f.matches} hits)`) : "";
      out.push(`     ${g} ${f.name}${where}${count}`);
      out.push(`       ${color.dim(f.description)}`);
      if (f.evidence) out.push(`       ${color.gray("> " + f.evidence)}`);
      if (opts.verbose) {
        out.push(`       ${color.dim("rule " + f.id)}`);
        for (const ref of f.references || []) out.push(`       ${color.dim("see " + ref)}`);
      }
    }
    out.push("");
  }

  out.push("  " + color.bold("Summary"));
  out.push(
    "  " +
      [
        severityColor("critical")(`critical ${result.countsBySeverity.critical || 0}`),
        severityColor("high")(`high ${result.countsBySeverity.high || 0}`),
        severityColor("medium")(`medium ${result.countsBySeverity.medium || 0}`),
        severityColor("low")(`low ${result.countsBySeverity.low || 0}`)
      ].join("   ")
  );
  const { likelyMalicious, review } = countVerdicts(records);
  out.push(
    "  " +
      color.dim(
        `${likelyMalicious} likely malicious (critical or high), ${review} worth a look (medium or low), ${result.stats.clean} clean`
      )
  );
  if (review) out.push("  " + color.dim("A medium or low finding is a reason to look at a file, not proof that it is malware."));
  out.push("");

  const roles = countSiteRoles(records);
  const siteFiles = Object.values(roles).reduce((a, b) => a + b, 0);
  if (siteFiles) {
    const breakdown = SITE_ROLES.filter((r) => roles[r]).map((r) => `${roles[r]} ${r}`).join(", ");
    out.push("  " + color.yellow(color.bold(`${siteFiles} flagged file${siteFiles === 1 ? " is" : "s are"} part of WordPress itself`)) + color.dim(` (${breakdown})`));
    out.push("  " + color.dim("Injected code inside a real file means the whole file is untrusted. Replace these with"));
    out.push("  " + color.dim("clean copies of the same version rather than only removing them:"));
    for (const role of SITE_ROLES) {
      if (!roles[role]) continue;
      const advice = records.find((r) => r.site && r.site.role === role).site.advice;
      out.push("  " + color.dim(`  ${role}: `) + color.gray(advice));
    }
    out.push("");
  }

  const targets = quoteTargets(result.targets);
  if (q) {
    const vault = path.resolve(q.vaultDir);
    const floor = q.minSeverity || SERIOUS_FROM;
    if (q.moved.length) {
      out.push("  " + color.bold(q.created
        ? `Created a quarantine vault and moved ${files(q.moved.length)} into it:`
        : `Moved ${files(q.moved.length)} into the quarantine vault at:`));
      out.push("  " + color.brand(`    ${vault}`));
      for (const line of vaultWarning(vault, result.targets)) out.push("  " + color.yellow(line));
      out.push("  " + color.dim("Put them back any time with:"));
      out.push("  " + color.brand(`    jaysift --restore --vault ${quoteTargets([vault])}`));
    } else {
      out.push("  " + color.bold("Nothing was moved.") + color.dim(` --quarantine moves ${levelsFrom(floor)} findings, and there are none.`));
    }
    if (q.skipped.length) {
      out.push("  " + color.dim(`Left ${files(q.skipped.length)} in place: ${levelsBelow(floor)} findings are reasons to look, not proof.`));
      out.push("  " + color.dim("To move those too:"));
      out.push("  " + color.brand(`    jaysift ${targets} --quarantine --quarantine-severity low`));
    }
    if (siteFiles && q.moved.length) {
      out.push("  " + color.yellow("WordPress files were moved too. If the site is offline now, restore them, then replace them with clean copies."));
    }
    out.push("");
  } else if (likelyMalicious) {
    out.push("  " + color.dim(`Review the findings, then move the ${files(likelyMalicious)} marked critical or high out of the site with:`));
    out.push("  " + color.brand(`    jaysift ${targets} --quarantine`));
    out.push("  " + color.dim("Quarantine moves files into a local vault. Put them back any time with --restore."));
    if (review) out.push("  " + color.dim(`It leaves the ${files(review)} marked medium or low where ${review === 1 ? "it is" : "they are"}.`));
    if (siteFiles) out.push("  " + color.dim("Quarantining the WordPress files above takes the site offline until you replace them."));
    out.push("");
  } else {
    out.push("  " + color.dim("Nothing here is likely to be malware. Look at the files above and decide."));
    out.push("  " + color.dim("--quarantine leaves them in place. To move them into the vault anyway:"));
    out.push("  " + color.brand(`    jaysift ${targets} --quarantine --quarantine-severity low`));
    out.push("");
  }

  return out.join("\n");
}

/** "critical and high", "critical, high and medium", and so on. */
function levelsFrom(floor) {
  const names = ["critical", "high", "medium", "low"].filter((s) => atLeast(s, floor));
  return names.length === 1 ? names[0] : names.slice(0, -1).join(", ") + " and " + names[names.length - 1];
}

function levelsBelow(floor) {
  const names = ["high", "medium", "low"].filter((s) => !atLeast(s, floor));
  return names.length === 1 ? names[0] : names.slice(0, -1).join(", ") + " and " + names[names.length - 1];
}

/**
 * A vault inside a scanned folder may sit inside the website. Say so, because
 * a folder a web server can reach is the wrong place to keep what was removed.
 */
export function vaultWarning(vault, targets) {
  const inside = (targets || []).some((t) => {
    const root = path.resolve(t);
    return vault === root || vault.startsWith(root + path.sep);
  });
  if (!inside) return [];
  return [
    "This vault is inside the folder you scanned. If that folder is served by a web server,",
    "move the vault out of it, or next time name a folder outside the site with --vault."
  ];
}

function quoteTargets(targets) {
  return targets
    .map((t) => (/\s/.test(t) ? `"${t}"` : t))
    .join(" ");
}

/** A stable, machine-readable object for --json output and CI pipelines. */
export function toJson(result, extra = {}) {
  const records = result.flagged || result.infected;
  const verdicts = countVerdicts(records);
  const flagged = records.map((r) => ({
    path: r.path,
    size: r.size,
    severity: r.findings[0].severity,
    verdict: atLeast(r.findings[0].severity, SERIOUS_FROM) ? "likely-malicious" : "review",
    site: r.site ? { type: r.site.type, role: r.site.role, root: r.site.root } : null,
    findings: r.findings.map((f) => ({
      rule: f.id,
      name: f.name,
      severity: f.severity,
      category: f.category,
      line: f.line,
      matches: f.matches || 1,
      evidence: f.evidence,
      description: f.description
    }))
  }));
  const q = extra.quarantine;
  return JSON.stringify(
    {
      tool: "JaySift",
      vendor: "JayHackPro",
      version: extra.version || null,
      startedAt: result.startedAt,
      durationMs: result.durationMs,
      targets: result.targets,
      sites: result.sites || [],
      summary: {
        scanned: result.stats.scanned,
        clean: result.stats.clean,
        flagged: records.length,
        likelyMalicious: verdicts.likelyMalicious,
        review: verdicts.review,
        infected: records.length,
        skippedLarge: result.stats.skippedLarge,
        unreadable: result.stats.unreadable,
        skippedDirs: result.stats.skippedDirs || 0,
        skippedDirNames: result.skippedDirNames || [],
        worstSeverity: worstSeverity(result),
        bySeverity: result.countsBySeverity,
        byCategory: result.countsByCategory
      },
      flagged,
      // The old name for "flagged". Kept so existing scripts keep working.
      infected: flagged,
      ...(q
        ? {
            quarantine: {
              vault: path.resolve(q.vaultDir),
              created: Boolean(q.created),
              dryRun: Boolean(q.dryRun),
              minSeverity: q.minSeverity || SERIOUS_FROM,
              moved: q.moved.map((m) => ({ path: m.path, id: m.id })),
              leftInPlace: (q.skipped || []).map((x) => ({ path: x.path, severity: x.severity })),
              failed: q.failed
            }
          }
        : {})
    },
    null,
    2
  );
}
