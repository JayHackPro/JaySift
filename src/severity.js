/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

/**
 * What a severity means.
 *
 * A finding is a reason to look at a file. How strong a reason depends on its
 * severity, and the report says so in plain words:
 *
 *   critical, high   likely malicious. The file matches something that is
 *                    rarely seen outside an attack.
 *   medium, low      worth a look. Unusual, and sometimes how an attack is
 *                    hidden, but ordinary sites have files like this too.
 *
 * JaySift never calls a file infected on a medium or low finding alone, and
 * --quarantine leaves such files where they are unless told otherwise.
 */

export const SEVERITIES = ["critical", "high", "medium", "low"];
export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/** The severity from which a file is called likely malicious, and quarantined by default. */
export const SERIOUS_FROM = "high";

/** The worst severity among a file's findings, or null if there are none. */
export function topSeverity(findings) {
  let top = null;
  for (const f of findings || []) {
    if ((SEVERITY_RANK[f.severity] || 0) > (SEVERITY_RANK[top] || 0)) top = f.severity;
  }
  return top;
}

/** Is this severity at or above another? */
export function atLeast(severity, floor) {
  return (SEVERITY_RANK[severity] || 0) >= (SEVERITY_RANK[floor] || 0);
}

/** "likely-malicious" for critical and high, "review" for medium and low. */
export function verdictFor(severity) {
  return atLeast(severity, SERIOUS_FROM) ? "likely-malicious" : "review";
}

/** How many flagged files fall under each verdict. */
export function countVerdicts(records) {
  const counts = { likelyMalicious: 0, review: 0 };
  for (const record of records || []) {
    if (verdictFor(record.severity || topSeverity(record.findings)) === "likely-malicious") counts.likelyMalicious++;
    else counts.review++;
  }
  return counts;
}
