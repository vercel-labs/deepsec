import { readFile } from "node:fs/promises";
import { parse as parseDotenv } from "dotenv";
import { atomicWriteFile } from "./atomic-file.js";

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

function serializeEnvValue(value: string): string {
  if (/^[A-Za-z0-9_./:@+-]*$/.test(value)) return value;
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`;
}

/** Parse credentials with the same dotenv dialect used at CLI startup. */
export function parseEnvFile(contents: string): Record<string, string> {
  return parseDotenv(contents);
}

/**
 * Atomically append or replace dotenv assignments while preserving all
 * unrelated bytes. The resulting file is always owner-readable/writable only.
 */
export async function updateEnvFile(
  filePath: string,
  updates: Readonly<Record<string, string>>,
): Promise<void> {
  for (const name of Object.keys(updates)) {
    if (!ENV_NAME.test(name)) throw new Error(`Invalid environment variable name: ${name}`);
  }

  let original = "";
  try {
    original = await readFile(filePath, "utf8");
  } catch (error: any) {
    if (error?.code !== "ENOENT") throw error;
  }

  const updateMap = new Map(Object.entries(updates));
  const pending = new Map(updateMap);
  const newline = original.includes("\r\n") ? "\r\n" : "\n";
  const lines = original.split(/\r?\n/);
  const rewritten = lines.map((line) => {
    const match = line.match(/^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=).*$/);
    if (!match || !updateMap.has(match[2])) return line;
    const value = updateMap.get(match[2])!;
    pending.delete(match[2]);
    return `${match[1]}${match[2]}${match[3]}${serializeEnvValue(value)}`;
  });

  let next = rewritten.join(newline);
  if (pending.size > 0) {
    if (next && !next.endsWith(newline)) next += newline;
    next += [...pending].map(([key, value]) => `${key}=${serializeEnvValue(value)}`).join(newline);
    next += newline;
  }

  await atomicWriteFile(filePath, next, { mode: 0o600 });
}

export async function loadEnvFile(
  filePath: string,
  target: NodeJS.ProcessEnv = process.env,
): Promise<Record<string, string>> {
  let parsed: Record<string, string> = {};
  try {
    parsed = parseEnvFile(await readFile(filePath, "utf8"));
  } catch (error: any) {
    if (error?.code !== "ENOENT") throw error;
  }
  Object.assign(target, parsed);
  return parsed;
}
