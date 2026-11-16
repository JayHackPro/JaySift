/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro® Inc. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

/**
 * Public programmatic API. Import this to embed JaySift in a build step,
 * a CI job, or a larger security service.
 *
 *   import { scan } from "jaysift";
 *   const result = await scan(["./public_html"]);
 */

export { scan, scanBuffer, worstSeverity, SEVERITY_RANK } from "./scanner.js";
export { SEVERITIES, SERIOUS_FROM, topSeverity, verdictFor, countVerdicts } from "./severity.js";
export { readPhp } from "./php.js";
export { walk, DEFAULT_SKIP_DIRS, skipDirsWithout } from "./walk.js";
export {
  findWordPressRoots,
  classifySiteFile,
  readWordPressVersion,
  countSiteRoles,
  SITE_ROLES
} from "./site.js";
export { RULES, rulesForKind, kindForPath } from "./rules.js";
export { runHeuristics, shannonEntropy } from "./heuristics.js";
export { KNOWN_BAD, sha256, matchHash, parseHashList } from "./hashes.js";
export {
  quarantineFiles,
  restoreFiles,
  listQuarantine,
  purgeQuarantine,
  loadManifest,
  QUARANTINE_DIR,
  LEGACY_QUARANTINE_DIR,
  defaultVaultDir
} from "./quarantine.js";
export { formatHuman, toJson, summaryLine, banner } from "./report.js";
export { EICAR, writeEicarSample, selfTest } from "./selftest.js";
