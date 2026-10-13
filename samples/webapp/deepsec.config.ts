import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { type DeepsecPlugin, defineConfig } from "deepsec/config";
import { webappDebugFlag } from "./matchers/webapp-debug-flag.js";
import { webappRouteNoRateLimit } from "./matchers/webapp-route-no-rate-limit.js";

const here = path.dirname(fileURLToPath(import.meta.url));

const webappPlugin: DeepsecPlugin = {
  name: "webapp-internal",
  matchers: [webappDebugFlag, webappRouteNoRateLimit],
};

export default defineConfig({
  ai: { mode: "gateway", provider: "vercel" },
  projects: [
    {
      id: "webapp",
      root: "./your-app",
      githubUrl: "https://github.com/acme/webapp/blob/main",
      infoMarkdown: fs.readFileSync(path.join(here, "INFO.md"), "utf-8"),
      promptAppend: "Pay extra attention to /api/admin/* and /api/billing/* surfaces.",
      priorityPaths: ["src/api/admin/", "src/api/billing/", "src/lib/auth/"],
    },
  ],
  plugins: [webappPlugin],
});
