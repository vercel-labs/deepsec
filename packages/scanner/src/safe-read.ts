import fs from "node:fs";
import path from "node:path";

const DEFAULT_MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024;

function maxScanFileBytes(): number {
  const raw = process.env.DEEPSEC_MAX_SCAN_FILE_BYTES;
  if (!raw) return DEFAULT_MAX_SCAN_FILE_BYTES;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_SCAN_FILE_BYTES;
}

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

export function isSafeRelativeFilePath(filePath: string): boolean {
  if (!filePath || filePath.includes("\0") || filePath.includes("\\")) return false;
  if (path.isAbsolute(filePath)) return false;
  return filePath.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

function isSafeRelativeEntryPath(relPath: string): boolean {
  if (relPath === "" || relPath === ".") return true;
  return isSafeRelativeFilePath(relPath);
}

function statEntryUnderRoot(absRoot: string, realRoot: string, relPath: string): fs.Stats | null {
  if (!isSafeRelativeEntryPath(relPath)) return null;
  const absPath = path.resolve(absRoot, relPath);
  if (!isInside(absRoot, absPath)) return null;

  try {
    const st = fs.lstatSync(absPath);
    if (st.isSymbolicLink()) return null;
    const real = fs.realpathSync(absPath);
    if (!isInside(realRoot, real)) return null;
    return st;
  } catch {
    return null;
  }
}

export function fileExistsUnderRoot(absRoot: string, realRoot: string, relPath: string): boolean {
  return statEntryUnderRoot(absRoot, realRoot, relPath)?.isFile() ?? false;
}

export function dirExistsUnderRoot(absRoot: string, realRoot: string, relPath: string): boolean {
  return statEntryUnderRoot(absRoot, realRoot, relPath)?.isDirectory() ?? false;
}

export function listDirUnderRoot(absRoot: string, realRoot: string, relPath: string): string[] {
  if (!isSafeRelativeEntryPath(relPath)) return [];
  const absPath = path.resolve(absRoot, relPath);
  if (!isInside(absRoot, absPath)) return [];

  try {
    const st = fs.lstatSync(absPath);
    if (st.isSymbolicLink() || !st.isDirectory()) return [];
    const real = fs.realpathSync(absPath);
    if (!isInside(realRoot, real)) return [];
    return fs.readdirSync(absPath);
  } catch {
    return [];
  }
}

export function readTextFileUnderRoot(
  absRoot: string,
  realRoot: string,
  relPath: string,
): string | null {
  if (!isSafeRelativeFilePath(relPath)) return null;
  const absPath = path.resolve(absRoot, relPath);
  if (!isInside(absRoot, absPath)) return null;

  try {
    const st = fs.lstatSync(absPath);
    if (st.isSymbolicLink() || !st.isFile()) return null;
    if (st.size > maxScanFileBytes()) return null;

    const real = fs.realpathSync(absPath);
    if (!isInside(realRoot, real)) return null;
  } catch {
    return null;
  }

  let fd: number | undefined;
  try {
    fd = fs.openSync(absPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.size > maxScanFileBytes()) return null;
    const buf = fs.readFileSync(fd);
    if (buf.includes(0)) return null;
    return buf.toString("utf-8").replaceAll("\r\n", "\n");
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {}
    }
  }
}
