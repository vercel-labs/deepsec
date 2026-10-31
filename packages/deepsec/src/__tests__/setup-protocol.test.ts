import { describe, expect, it } from "vitest";
import {
  formatSetupErrorHuman,
  SetupProtocolError,
  setSetupDocumentationWorkspace,
  setupErrorExitCode,
  setupErrorPayload,
} from "../setup/protocol.js";

describe("headless setup protocol", () => {
  it("serializes actionable needs-input errors without secrets", () => {
    const error = new SetupProtocolError({
      code: "VERCEL_AUTH_REQUIRED",
      message: "Authenticate with Vercel.",
      missingInputs: ["vercel.authentication"],
      actions: [{ id: "login", description: "Log in.", commands: ["npx vercel login"] }],
    });

    expect(setupErrorExitCode(error)).toBe(2);
    expect(setupErrorPayload(error)).toMatchObject({
      type: "needs_input",
      code: "VERCEL_AUTH_REQUIRED",
    });
    expect(formatSetupErrorHuman(error)).toContain("npx vercel login");
  });

  it("uses a distinct exit code for resumable limits", () => {
    expect(
      setupErrorExitCode(
        new SetupProtocolError({ code: "COST_LIMIT_REACHED", message: "Stopped", kind: "limit" }),
      ),
    ).toBe(3);
  });

  it("points agents at documentation installed in the isolated workspace", () => {
    setSetupDocumentationWorkspace("/tmp/example/.deepsec");
    const error = new SetupProtocolError({ code: "SETUP_STOPPED", message: "Stopped" });
    const payload = setupErrorPayload(error);

    expect(payload.documentation).toMatchObject({
      skill: "/tmp/example/.deepsec/node_modules/deepsec/SKILL.md",
      gettingStarted: "/tmp/example/.deepsec/node_modules/deepsec/dist/docs/getting-started.md",
      vercelSetup: "/tmp/example/.deepsec/node_modules/deepsec/dist/docs/vercel-setup.md",
    });
    expect(formatSetupErrorHuman(error)).toContain(
      "cat '/tmp/example/.deepsec/node_modules/deepsec/SKILL.md'",
    );
  });
});
