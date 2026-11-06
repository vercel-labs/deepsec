import { execSync } from "node:child_process";
import path from "node:path";

/**
 * Bundle e2e runs `packages/deepsec/dist/cli.mjs`. Always rebuild before the
 * e2e project so tests never execute a stale dist/ from an older checkout.
 */
export default function globalSetup(): void {
  const root = path.resolve(import.meta.dirname, "..");
  execSync("pnpm bundle", { cwd: root, stdio: "inherit", env: process.env });
}
