import path from "node:path";
import { describe, expect, it } from "vitest";
import { deterministicVercelProjectName } from "../setup/project-name.js";

describe("deterministic Vercel project name", () => {
  it("is stable per project checkout and shared by init/setup", () => {
    const root = path.resolve("/tmp/example/app");
    const first = deterministicVercelProjectName("My App", root);
    expect(first).toMatch(/^deepsec-my-app-[a-f0-9]{8}$/);
    expect(deterministicVercelProjectName("My App", root)).toBe(first);
    expect(deterministicVercelProjectName("My App", `${root}-other`)).not.toBe(first);
  });
});
