import type { MatcherPlugin } from "@deepsec/core";
import { makeRe, minimatch } from "minimatch";
import { z } from "zod";
import { regexMatcher } from "./matchers/utils.js";

const MAX_REGEX_LENGTH = 500;
const MAX_GLOB_LENGTH = 240;
const MAX_EXAMPLE_LENGTH = 10_000;

const allowedFlagsSchema = z.enum(["i", "m", "im"]);

function regexSafetyError(source: string): string | undefined {
  if (source.length > MAX_REGEX_LENGTH) {
    return `must be at most ${MAX_REGEX_LENGTH} characters`;
  }
  if (source.includes("\0")) return "must not contain NUL bytes";
  if (/\\[1-9]/.test(source) || /\\k[<{]/.test(source)) {
    return "backreferences are not supported";
  }
  if (/\(\?<([=!])/.test(source)) return "lookbehind assertions are not supported";

  // These conservative checks reject the common exponential-time shapes. The
  // setup agent writes coverage matchers, so it does not need regex features
  // whose safety depends on subtle engine backtracking behavior.
  const atom = String.raw`(?:\\.|\[[^\]]*\]|[^()[\]\\])`;
  const nestedQuantifier = new RegExp(
    String.raw`\((?:${atom})*(?:[*+]|\{\d+(?:,\d*)?\})(?:${atom})*\)\s*(?:[*+]|\{\d+(?:,\d*)?\})`,
  );
  if (nestedQuantifier.test(source)) return "nested quantifiers are not supported";

  const quantifiedAlternation = new RegExp(
    String.raw`\((?:${atom})*\|(?:${atom})*\)\s*(?:[*+]|\{\d+(?:,\d*)?\})`,
  );
  if (quantifiedAlternation.test(source)) {
    return "quantified alternations are not supported";
  }
  if (/(?:\.\*|\.\+)[^|\n]{0,80}(?:\.\*|\.\+)/.test(source)) {
    return "multiple wildcard repetitions are not supported";
  }
  for (const match of source.matchAll(/\{(\d+)(?:,(\d*))?\}/g)) {
    const upper = match[2] === undefined ? Number(match[1]) : Number(match[2] || match[1]);
    if (upper > 1_000) return "repeat counts greater than 1000 are not supported";
  }

  try {
    const regex = new RegExp(source);
    if (regex.test("")) return "must not match an empty string";
  } catch (error) {
    return error instanceof Error
      ? `is not a valid regular expression: ${error.message}`
      : "is invalid";
  }
  return undefined;
}

function globSafetyError(pattern: string): string | undefined {
  if (pattern.length > MAX_GLOB_LENGTH) {
    return `must be at most ${MAX_GLOB_LENGTH} characters`;
  }
  if (/[\x00-\x1f\x7f]/.test(pattern)) return "must not contain control characters";
  if (pattern.includes("\\")) return "must use forward slashes";
  if (pattern.startsWith("!") || pattern.startsWith("#")) {
    return "negated and comment globs are not supported";
  }
  if (pattern.startsWith("/") || /^[A-Za-z]:\//.test(pattern)) {
    return "must be relative to the repository root";
  }
  if (pattern.split("/").some((part) => part === ".." || part === ".")) {
    return "must not contain traversal segments";
  }
  const braceGroups = pattern.match(/\{/g)?.length ?? 0;
  const braceAlternatives = pattern.match(/,/g)?.length ?? 0;
  const stars = pattern.match(/\*/g)?.length ?? 0;
  if (braceGroups > 3 || braceAlternatives > 16 || stars > 12) {
    return "is too complex to compile safely";
  }
  if (/^(?:\*|\*\*|\*\*\/\*+\/?|\*\*\/\*\*\/?)$/.test(pattern)) {
    return "is too broad; constrain it by directory, filename, or extension";
  }
  if (!/[A-Za-z0-9]/.test(pattern)) {
    return "is too broad; include a literal directory, filename, or extension";
  }
  try {
    if (!makeRe(pattern, { nonegate: true, nocomment: true })) return "is not a valid glob";
    const breadthProbes = ["README.md", "src/index.ts", ".env", "deep/a/config.yaml"];
    if (
      breadthProbes.every((file) =>
        minimatch(file, pattern, { dot: true, nonegate: true, nocomment: true }),
      )
    ) {
      return "is too broad; constrain it by directory, filename, or extension";
    }
  } catch (error) {
    return error instanceof Error ? `is not a valid glob: ${error.message}` : "is not a valid glob";
  }
  return undefined;
}

const safeGlobSchema = z
  .string()
  .trim()
  .min(1)
  .superRefine((pattern, ctx) => {
    const message = globSafetyError(pattern);
    if (message) ctx.addIssue({ code: z.ZodIssueCode.custom, message });
  });

const regexPatternSchema = z
  .object({
    source: z.string().min(1),
    flags: allowedFlagsSchema.optional(),
    label: z.string().trim().min(1).max(240),
  })
  .strict()
  .superRefine(({ source, flags }, ctx) => {
    const message = regexSafetyError(source);
    if (message) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["source"], message });
      return;
    }
    try {
      new RegExp(source, flags);
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["source"],
        message: error instanceof Error ? error.message : "invalid regular expression",
      });
    }
  });

/** Strict data-only format accepted from the setup agent. */
export const declarativeMatcherSpecSchema = z
  .object({
    version: z.literal(1),
    slug: z
      .string()
      .trim()
      .min(1)
      .max(80)
      .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, "must be a lowercase kebab-case slug"),
    description: z.string().trim().min(1).max(500),
    noiseTier: z.enum(["precise", "normal", "noisy"]),
    filePatterns: z.array(safeGlobSchema).min(1).max(32),
    requires: z
      .object({
        tech: z.array(z.string().trim().min(1).max(80)).min(1).max(32).optional(),
        sentinelFiles: z.array(safeGlobSchema).min(1).max(32).optional(),
      })
      .strict()
      .refine((gate) => gate.tech !== undefined || gate.sentinelFiles !== undefined, {
        message: "must include tech or sentinelFiles",
      })
      .optional(),
    patterns: z.array(regexPatternSchema).min(1).max(32),
    excludeFilePatterns: z.array(safeGlobSchema).min(1).max(32).optional(),
    examples: z.array(z.string().min(1).max(MAX_EXAMPLE_LENGTH)).min(1).max(64),
    closesSurfaceIds: z
      .array(
        z
          .string()
          .trim()
          .min(1)
          .max(120)
          .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, "must be a lowercase kebab-case identifier"),
      )
      .min(1)
      .max(64)
      .refine((ids) => new Set(ids).size === ids.length, "must not contain duplicates"),
  })
  .strict()
  .superRefine((spec, ctx) => {
    const regexes = spec.patterns.map(({ source, flags }) => new RegExp(source, flags));
    for (const [index, example] of spec.examples.entries()) {
      if (!regexes.some((regex) => regex.test(example))) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["examples", index],
          message: "must be matched by at least one declared pattern",
        });
      }
    }
  });

export type DeclarativeMatcherSpec = z.infer<typeof declarativeMatcherSpecSchema>;

/** Complete setup-agent response schema, including cross-spec slug uniqueness. */
export const declarativeMatcherSpecsSchema = z
  .array(declarativeMatcherSpecSchema)
  .max(64)
  .superRefine((specs, ctx) => {
    const seen = new Set<string>();
    for (const [index, spec] of specs.entries()) {
      if (seen.has(spec.slug)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [index, "slug"],
          message: `duplicate matcher slug: ${spec.slug}`,
        });
      }
      seen.add(spec.slug);
    }
  });

export interface DeclarativeMatcherPlugin extends MatcherPlugin {
  /** Coverage inventory IDs this generated matcher was accepted to close. */
  closesSurfaceIds: string[];
  /** Validated, detached data used to produce this plugin. */
  declarativeSpec: DeclarativeMatcherSpec;
}

export interface CompileDeclarativeMatcherOptions {
  /** Slugs already registered by built-in, user, or earlier generated matchers. */
  existingSlugs?: Iterable<string>;
}

function cloneSpec(spec: DeclarativeMatcherSpec): DeclarativeMatcherSpec {
  return structuredClone(spec);
}

/** Validate untrusted JSON and compile it without evaluating generated code. */
export function compileDeclarativeMatcher(
  input: unknown,
  options: CompileDeclarativeMatcherOptions = {},
): DeclarativeMatcherPlugin {
  const spec = declarativeMatcherSpecSchema.parse(input);
  if (new Set(options.existingSlugs).has(spec.slug)) {
    throw new Error(`Duplicate matcher slug: ${spec.slug}`);
  }

  const patterns = spec.patterns.map(({ source, flags, label }) => ({
    regex: new RegExp(source, flags),
    label,
  }));
  const excluded = (spec.excludeFilePatterns ?? []).map((glob) =>
    makeRe(glob, { dot: true, nonegate: true, nocomment: true }),
  );
  const detachedSpec = cloneSpec(spec);

  return {
    slug: spec.slug,
    description: spec.description,
    noiseTier: spec.noiseTier,
    filePatterns: [...spec.filePatterns],
    requires: spec.requires
      ? {
          tech: spec.requires.tech ? [...spec.requires.tech] : undefined,
          sentinelFiles: spec.requires.sentinelFiles ? [...spec.requires.sentinelFiles] : undefined,
        }
      : undefined,
    examples: [...spec.examples],
    closesSurfaceIds: [...spec.closesSurfaceIds],
    declarativeSpec: detachedSpec,
    match(content, filePath) {
      const normalizedPath = filePath.replaceAll("\\", "/");
      if (excluded.some((pattern) => pattern !== false && pattern.test(normalizedPath))) {
        return [];
      }
      return regexMatcher(spec.slug, patterns, content);
    },
  };
}

/** Compile a complete generated set, rejecting duplicates within and outside it. */
export function compileDeclarativeMatchers(
  inputs: readonly unknown[],
  options: CompileDeclarativeMatcherOptions = {},
): DeclarativeMatcherPlugin[] {
  const specs = declarativeMatcherSpecsSchema.parse(inputs);
  const slugs = new Set(options.existingSlugs);
  return specs.map((spec) => {
    const matcher = compileDeclarativeMatcher(spec, { existingSlugs: slugs });
    slugs.add(matcher.slug);
    return matcher;
  });
}
