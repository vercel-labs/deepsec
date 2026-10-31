import fs from "node:fs";
import path from "node:path";
import { SetupProtocolError } from "./protocol.js";

interface LockRecord {
  pid: number;
  startedAt: string;
  command: string[];
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error: any) {
    return error?.code !== "ESRCH";
  }
}

export function acquireSetupLock(workspaceDir: string): () => void {
  const file = path.join(path.resolve(workspaceDir), ".deepsec-setup.lock");
  const record: LockRecord = {
    pid: process.pid,
    startedAt: new Date().toISOString(),
    command: process.argv.slice(1),
  };
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const descriptor = fs.openSync(file, "wx", 0o600);
      fs.writeFileSync(descriptor, `${JSON.stringify(record, null, 2)}\n`);
      fs.closeSync(descriptor);
      let released = false;
      return () => {
        if (released) return;
        released = true;
        try {
          const current = JSON.parse(fs.readFileSync(file, "utf8")) as LockRecord;
          if (current.pid === process.pid) fs.unlinkSync(file);
        } catch {}
      };
    } catch (error: any) {
      if (error?.code !== "EEXIST") throw error;
      let owner: LockRecord | undefined;
      try {
        owner = JSON.parse(fs.readFileSync(file, "utf8")) as LockRecord;
      } catch {}
      if (attempt === 0 && (!owner || !processIsAlive(owner.pid))) {
        try {
          fs.unlinkSync(file);
          continue;
        } catch {}
      }
      throw new SetupProtocolError({
        code: "SETUP_ALREADY_RUNNING",
        kind: "failure",
        message: `Another Deepsec setup is already running${owner ? ` (PID ${owner.pid}, started ${owner.startedAt})` : ""}.`,
        details: owner ? { owner } : undefined,
      });
    }
  }
  throw new Error("Could not acquire setup lock");
}
