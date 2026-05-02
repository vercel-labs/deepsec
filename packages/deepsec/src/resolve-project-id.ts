import { getConfig } from "@deepsec/core";

// Strict allowlist for project ids. Catches `..`, path separators, shell
// metacharacters, and whitespace in one place — every CLI entry point and
// every config-supplied id flows through here, so downstream callers
// (path joins, sandbox `sh -c` interpolation, git commit messages) can
// treat the value as opaque.
const PROJECT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function validateProjectId(id: string): string {
  if (!PROJECT_ID_RE.test(id)) {
    throw new Error(
      `Invalid project id ${JSON.stringify(id)}: must match ${PROJECT_ID_RE} ` +
        `(letters, digits, '.', '_', '-'; up to 64 chars; must not start with a separator).`,
    );
  }
  return id;
}

/**
 * Resolve a project id from CLI input or the loaded config.
 *
 * Precedence:
 *   1. The `--project-id` value the user passed (always wins).
 *   2. The single entry of `projects[]` if the config has exactly one.
 *
 * Throws with actionable guidance when neither path resolves to a unique
 * project — i.e. config has zero projects, or has multiple and the user
 * didn't disambiguate.
 */
export function resolveProjectId(provided: string | undefined): string {
  if (provided) return validateProjectId(provided);

  const config = getConfig();
  const projects = config?.projects ?? [];

  if (projects.length === 1) return validateProjectId(projects[0].id);

  if (projects.length === 0) {
    throw new Error(
      `No --project-id specified and no projects found in deepsec.config.ts.\n` +
        `  Run \`deepsec init\` to scaffold a workspace, or add an entry to\n` +
        `  the projects[] array in your existing deepsec.config.ts.`,
    );
  }

  const ids = projects.map((p) => p.id).join(", ");
  throw new Error(
    `Multiple projects in deepsec.config.ts: ${ids}.\n` + `  Pass --project-id <id> to pick one.`,
  );
}

export { validateProjectId };
