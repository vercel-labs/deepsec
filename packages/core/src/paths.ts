import path from "node:path";

export function getDataRoot(): string {
  return process.env.DEEPSEC_DATA_ROOT || "data";
}

// Reject empty, '.', '..', absolute paths, null bytes, and any path
// separator. Used at every entry point that joins user-supplied segments
// onto a per-project mirror so a `../`-laced projectId/runId can't escape
// the mirror or clobber a sibling project's files.
export function assertSafeSegment(name: string, label = "segment"): void {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error(`Invalid ${label}: must be a non-empty string`);
  }
  if (name === "." || name === "..") {
    throw new Error(`Invalid ${label}: ${JSON.stringify(name)}`);
  }
  if (name.includes("\0")) {
    throw new Error(`Invalid ${label}: contains null byte`);
  }
  if (name.includes("/") || name.includes("\\")) {
    throw new Error(`Invalid ${label}: contains path separator`);
  }
  if (path.isAbsolute(name)) {
    throw new Error(`Invalid ${label}: must not be absolute`);
  }
}

// FilePath is a relative path under a project root that may contain
// forward-slash directory separators (record paths come from glob output).
// We allow `/` between segments but still reject `..` components, absolute
// paths, null bytes, and backslashes (which would otherwise be folded into
// path separators on Windows).
export function assertSafeFilePath(filePath: string): void {
  if (typeof filePath !== "string" || filePath.length === 0) {
    throw new Error("Invalid filePath: must be a non-empty string");
  }
  if (filePath.includes("\0")) {
    throw new Error("Invalid filePath: contains null byte");
  }
  if (filePath.includes("\\")) {
    throw new Error("Invalid filePath: contains backslash");
  }
  if (path.isAbsolute(filePath)) {
    throw new Error("Invalid filePath: must not be absolute");
  }
  for (const part of filePath.split("/")) {
    if (part === "" || part === "." || part === "..") {
      throw new Error(`Invalid filePath: contains "${part}" segment`);
    }
  }
}

export function dataDir(projectId: string): string {
  assertSafeSegment(projectId, "projectId");
  return path.join(getDataRoot(), projectId);
}

export function projectConfigPath(projectId: string): string {
  return path.join(dataDir(projectId), "project.json");
}

// --- File records (permanent per-file mirror) ---

export function filesDir(projectId: string): string {
  return path.join(dataDir(projectId), "files");
}

export function fileRecordPath(projectId: string, filePath: string): string {
  assertSafeFilePath(filePath);
  return path.join(filesDir(projectId), filePath + ".json");
}

// --- Runs (lightweight metadata) ---

export function runsDir(projectId: string): string {
  return path.join(dataDir(projectId), "runs");
}

export function runMetaPath(projectId: string, runId: string): string {
  assertSafeSegment(runId, "runId");
  return path.join(runsDir(projectId), runId + ".json");
}

// --- Reports ---

export function reportsDir(projectId: string): string {
  return path.join(dataDir(projectId), "reports");
}

export function reportJsonPath(projectId: string, runId?: string): string {
  if (runId !== undefined) assertSafeSegment(runId, "runId");
  const name = runId ? `report-${runId}.json` : "report.json";
  return path.join(reportsDir(projectId), name);
}

export function reportMdPath(projectId: string, runId?: string): string {
  if (runId !== undefined) assertSafeSegment(runId, "runId");
  const name = runId ? `report-${runId}.md` : "report.md";
  return path.join(reportsDir(projectId), name);
}

export function reportCsvPath(projectId: string, runId?: string): string {
  if (runId !== undefined) assertSafeSegment(runId, "runId");
  const name = runId ? `report-${runId}.csv` : "report.csv";
  return path.join(reportsDir(projectId), name);
}
