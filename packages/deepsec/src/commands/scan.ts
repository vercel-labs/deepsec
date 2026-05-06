import fs from "node:fs";
import path from "node:path";
import { findProject, getConfigPath, loadAllFileRecords, projectConfigPath } from "@deepsec/core";
import { scan } from "@deepsec/scanner";
import { BOLD, CYAN, DIM, GREEN, RESET, YELLOW } from "../formatters.js";
import { requireExistingDir } from "../require-dir.js";
import { resolveProjectId } from "../resolve-project-id.js";

/**
 * Resolve the root directory to scan, in precedence order:
 *   1. `--root` flag (override; required for first-time scans, sandbox runs)
 *   2. `findProject(id).root` from the loaded `deepsec.config.ts`
 *      (resolved relative to the config file's directory)
 *   3. `data/<id>/project.json:rootPath` from a prior run
 *   4. Throw with actionable guidance.
 *
 * Every resolved path is verified to exist and be a directory.
 */
function resolveScanRoot(opts: { projectId: string; root?: string }): string {
  if (opts.root) {
    return requireExistingDir(opts.root, "--root");
  }

  const projectFromConfig = findProject(opts.projectId);
  const configPath = getConfigPath();
  if (projectFromConfig && configPath) {
    const configDir = path.dirname(configPath);
    const resolved = path.resolve(configDir, projectFromConfig.root);
    return requireExistingDir(resolved, `deepsec.config.ts (${configPath})`);
  }

  const projectJsonPath = projectConfigPath(opts.projectId);
  if (fs.existsSync(projectJsonPath)) {
    const stored = JSON.parse(fs.readFileSync(projectJsonPath, "utf-8"));
    if (typeof stored.rootPath === "string") {
      return requireExistingDir(stored.rootPath, `${projectJsonPath}:rootPath`);
    }
  }

  throw new Error(
    `No root path for project "${opts.projectId}".\n` +
      `  Pass --root <path>, or add the project to deepsec.config.ts:\n` +
      `    projects: [{ id: "${opts.projectId}", root: "<path>" }]`,
  );
}

/** Right-pad a string to a fixed width, accounting for ANSI escape codes. */
function pad(s: string, width: number): string {
  // Strip ANSI codes for length calc; pad based on visible width.
  const visibleLen = s.replace(/\x1b\[[0-9;]*m/g, "").length;
  return visibleLen >= width ? s : s + " ".repeat(width - visibleLen);
}

export async function scanCommand(opts: { projectId?: string; root?: string; matchers?: string }) {
  const projectId = resolveProjectId(opts.projectId);
  const matcherSlugs = opts.matchers ? opts.matchers.split(",").map((s) => s.trim()) : undefined;
  const resolvedRoot = resolveScanRoot({ projectId, root: opts.root });

  console.log(`${BOLD}Scanning${RESET} ${resolvedRoot} for project ${BOLD}${projectId}${RESET}`);
  if (matcherSlugs) {
    console.log(`${DIM}Filtered matchers:${RESET} ${matcherSlugs.join(", ")}`);
  }

  // Per-matcher hit counts collected from progress events. Used in the
  // post-scan summary so we don't have to re-derive it from records.
  const hitsBySlug = new Map<string, number>();
  let filesWithMatches = 0;
  let totalFileMatches = 0;
  const startedAt = Date.now();

  let pastGlobbing = false;
  let globsDone = 0;
  let globsTotal = 0;

  // Progress-bar state. We learn `matcherTotal` from the first
  // matcher_started event, then redraw on every matcher_done. Throttled
  // to ~20fps on TTY; on non-TTY we drop one heartbeat line per
  // quartile so log files don't fill with redraw spam.
  let matcherTotal = 0;
  let matcherIdx = 0;
  let currentMatcher = "";
  let lastBarRender = 0;
  let lastBarMilestone = -1;
  const renderBar = (force = false) => {
    if (!pastGlobbing || matcherTotal === 0) return;
    const matchCount = totalFileMatches;
    if (process.stdout.isTTY) {
      const now = Date.now();
      if (!force && now - lastBarRender < 50) return;
      lastBarRender = now;
      const width = 24;
      const ratio = Math.min(1, matcherIdx / matcherTotal);
      const filled = Math.round(ratio * width);
      const bar = "█".repeat(filled) + "░".repeat(width - filled);
      const pct = Math.round(ratio * 100)
        .toString()
        .padStart(3, " ");
      const slug = currentMatcher ? ` ${DIM}${currentMatcher}${RESET}` : "";
      // Truncate the slug column so a long name + numbers don't wrap on
      // narrow terminals. ANSI codes don't count toward visible width.
      process.stdout.write(
        `\r  ${BOLD}${bar}${RESET} ${pct}% ${DIM}(${matcherIdx}/${matcherTotal} matchers, ${matchCount} hit${matchCount === 1 ? "" : "s"})${RESET}${slug}\x1b[K`,
      );
    } else {
      // Quartile heartbeats so CI logs / redirected stdout still show
      // progress without a flood of redraws.
      const quartile = Math.min(4, Math.floor((matcherIdx / matcherTotal) * 4));
      if (force || quartile > lastBarMilestone) {
        lastBarMilestone = quartile;
        console.log(
          `${DIM}  Progress ${matcherIdx}/${matcherTotal} matchers — ${matchCount} hit${matchCount === 1 ? "" : "s"} so far${RESET}`,
        );
      }
    }
  };

  const result = await scan({
    projectId,
    root: resolvedRoot,
    matcherSlugs,
    onProgress(progress) {
      // Globbing phase: collapse to a single re-rendered line so we don't
      // print 50+ "Globbing pattern X/Y" rows on big projects.
      if (progress.matcherSlug === "glob") {
        if (progress.type === "matcher_started") {
          const match = progress.message.match(/(\d+)\/(\d+)/);
          if (match) {
            globsDone = Number(match[1]);
            globsTotal = Number(match[2]);
          }
          if (process.stdout.isTTY) {
            process.stdout.write(
              `\r${DIM}  Discovering files… ${globsDone}/${globsTotal}${RESET}\x1b[K`,
            );
          } else if (globsDone === 1 || globsDone === globsTotal) {
            console.log(`${DIM}  Discovering files… ${globsDone}/${globsTotal}${RESET}`);
          }
        }
        return;
      }

      if (!pastGlobbing) {
        pastGlobbing = true;
        if (process.stdout.isTTY) process.stdout.write("\r\x1b[K");
        if (!process.stdout.isTTY) {
          // Non-TTY only: print a header so heartbeat lines have context.
          console.log(`${DIM}  Running matchers…${RESET}`);
        }
      }

      switch (progress.type) {
        case "matcher_started":
          if (progress.matcherTotal && matcherTotal === 0) {
            matcherTotal = progress.matcherTotal;
          }
          if (progress.matcherIndex) matcherIdx = progress.matcherIndex;
          currentMatcher = progress.matcherSlug ?? "";
          renderBar();
          break;
        case "matcher_done":
          if (progress.matcherSlug && (progress.matchCount ?? 0) > 0) {
            hitsBySlug.set(progress.matcherSlug, progress.matchCount ?? 0);
          }
          if (progress.matcherIndex) matcherIdx = progress.matcherIndex;
          renderBar();
          break;
        case "file_scanned":
          filesWithMatches++;
          totalFileMatches += progress.matchCount ?? 0;
          // File-scanned can fire many times per matcher; piggyback on
          // the rate-limited renderBar so the hit counter ticks up live.
          renderBar();
          break;
      }
    },
  });
  // Final bar render (force) and clear-line so the summary that follows
  // starts on a fresh line.
  renderBar(true);
  if (process.stdout.isTTY) process.stdout.write("\r\x1b[K");
  const elapsedMs = Date.now() - startedAt;

  // ------------------------------------------------------------------
  // Summary section — the actually-useful output.
  // ------------------------------------------------------------------
  console.log();
  console.log(`${BOLD}Detected tech${RESET}`);
  if (result.detected.tags.length > 0) {
    // Print up to 6 tags per row so a polyglot repo doesn't wrap weirdly.
    const tags = result.detected.tags;
    for (let i = 0; i < tags.length; i += 6) {
      console.log(`  ${tags.slice(i, i + 6).join(", ")}`);
    }
  } else {
    console.log(`  ${DIM}(none — no manifests / lockfiles recognized)${RESET}`);
  }
  const totalMatchers = result.activeMatchers.length + result.skippedMatchers.length;
  console.log(
    `  ${DIM}${result.activeMatchers.length}/${totalMatchers} matchers active${RESET}` +
      (result.skippedMatchers.length > 0
        ? ` ${DIM}(${result.skippedMatchers.length} dormant — your repo doesn't use those frameworks)${RESET}`
        : ""),
  );

  // Per-language coverage table — what we scanned, what we matched.
  if (result.languageStats.length > 0) {
    console.log();
    console.log(`${BOLD}Coverage by language${RESET}`);
    const sorted = [...result.languageStats].sort((a, b) => b.scannedFiles - a.scannedFiles);
    for (const stat of sorted) {
      const pct = stat.scannedFiles === 0 ? 0 : stat.matchRate * 100;
      const pctStr = pct.toFixed(pct < 1 ? 2 : 1) + "%";
      const isLow = stat.scannedFiles >= 50 && stat.matchRate < 0.01;
      const colored = isLow ? `${YELLOW}${pctStr}${RESET}` : pctStr;
      console.log(
        `  ${pad(stat.language, 11)} ${pad(String(stat.scannedFiles) + " files", 12)} ${pad(String(stat.candidates) + " hits", 12)} ${colored}`,
      );
    }
  }

  // Top slugs that produced candidates — grouped, alphabetical inside.
  if (hitsBySlug.size > 0) {
    console.log();
    console.log(`${BOLD}Matchers that fired${RESET}`);
    const sorted = [...hitsBySlug.entries()].sort((a, b) => b[1] - a[1]);
    const top = sorted.slice(0, 12);
    for (const [slug, count] of top) {
      console.log(`  ${pad(slug, 36)} ${DIM}${count} match${count === 1 ? "" : "es"}${RESET}`);
    }
    if (sorted.length > top.length) {
      console.log(`  ${DIM}… and ${sorted.length - top.length} more matcher(s) with hits${RESET}`);
    }
  }

  // Top files by candidate count — gives the user a fast sense of where
  // findings will concentrate before they even run process.
  try {
    const records = loadAllFileRecords(projectId);
    const topFiles = records
      .filter((r) => r.candidates.length > 0)
      .sort((a, b) => b.candidates.length - a.candidates.length)
      .slice(0, 5);
    if (topFiles.length > 0) {
      console.log();
      console.log(`${BOLD}Top files by candidate count${RESET}`);
      for (const r of topFiles) {
        const slugs = Array.from(new Set(r.candidates.map((c) => c.vulnSlug))).slice(0, 4);
        const slugList =
          slugs.join(", ") +
          (slugs.length < new Set(r.candidates.map((c) => c.vulnSlug)).size ? ", …" : "");
        console.log(
          `  ${pad(r.filePath, 56)} ${DIM}${r.candidates.length} hit${r.candidates.length === 1 ? "" : "s"} (${slugList})${RESET}`,
        );
      }
    }
  } catch {
    // Best-effort — if records can't be loaded, skip this section.
  }

  // Low-coverage warnings stay loud. They're the signal users on niche
  // stacks need to see — silent zero candidates is the worst outcome.
  const lowCoverage = result.languageStats.filter(
    (s) => s.scannedFiles >= 50 && s.matchRate < 0.01,
  );
  for (const stat of lowCoverage) {
    const pct = (stat.matchRate * 100).toFixed(2);
    const severity = stat.matchRate < 0.002 ? "very low" : "low";
    console.log();
    console.log(
      `${YELLOW}⚠ Low matcher coverage for ${stat.language}${RESET} ${DIM}(${severity})${RESET}`,
    );
    console.log(
      `  Scanned ${stat.scannedFiles} ${stat.language} file(s) but produced ${stat.candidates} candidate(s) (${pct}%).`,
    );
    console.log(
      `  ${DIM}deepsec may not have built-in matchers for your ${stat.language} stack.${RESET}`,
    );
    console.log(
      `  ${DIM}See docs/writing-matchers.md for how to add a custom matcher plugin.${RESET}`,
    );
  }

  // Final tally + next steps.
  console.log();
  const elapsedSec = (elapsedMs / 1000).toFixed(1);
  console.log(
    `${GREEN}Scan complete${RESET} ${DIM}in ${elapsedSec}s${RESET}` +
      ` ${DIM}—${RESET} ${BOLD}${result.candidateCount}${RESET} file(s) with candidates` +
      `, ${BOLD}${totalFileMatches || filesWithMatches}${RESET} total matches`,
  );
  console.log(`${DIM}Run ID: ${result.runId}${RESET}`);

  console.log();
  console.log(`${BOLD}Next${RESET}`);
  console.log(`  ${CYAN}pnpm deepsec process --project-id ${projectId}${RESET}`);
  if (result.candidateCount === 0) {
    console.log(
      `  ${DIM}(no candidates yet — consider widening matchers or writing custom ones)${RESET}`,
    );
  } else if (result.candidateCount > 200) {
    console.log(
      `  ${DIM}Large candidate set — consider --only-slugs or --filter <path> to focus the AI run${RESET}`,
    );
  }
}
