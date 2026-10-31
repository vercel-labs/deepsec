import fs from "node:fs";
import { mkdir, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

function temporaryPath(file: string): string {
  return `${file}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
}

export function atomicWriteFileSync(
  file: string,
  contents: string,
  options: { mode?: number } = {},
): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = temporaryPath(file);
  try {
    fs.writeFileSync(temp, contents, { encoding: "utf8", mode: options.mode });
    fs.renameSync(temp, file);
  } finally {
    if (fs.existsSync(temp)) fs.unlinkSync(temp);
  }
}

export async function atomicWriteFile(
  file: string,
  contents: string,
  options: { mode?: number } = {},
): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temp = temporaryPath(file);
  try {
    await writeFile(temp, contents, { encoding: "utf8", mode: options.mode });
    await rename(temp, file);
  } finally {
    await unlink(temp).catch(() => undefined);
  }
}
