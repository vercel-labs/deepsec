import {
  Cursor,
  type ModelListItem,
  type ModelParameterDefinition,
  type ModelParameterValue,
  type ModelSelection,
} from "@cursor/sdk";

export const DEFAULT_CURSOR_MODEL = "composer-2.5";

const DEFAULT_CURSOR_MODEL_PARAMS: ModelParameterValue[] = [{ id: "fast", value: "false" }];
const DEFAULT_CATALOG_CACHE_KEY = "__cursor-default__";

interface CursorModelCatalog {
  modelsById: Map<string, ModelListItem>;
  aliasesToId: Map<string, string>;
  ambiguousAliases: Map<string, string[]>;
  slugsToSelection: Map<string, ModelSelection>;
  ambiguousSlugs: Map<string, ModelSelection[]>;
  supportedSlugsByModelId: Map<string, string[]>;
  modelOptionsById: Map<string, CursorModelOptions>;
  supportedOptionsByModelId: Map<string, string[]>;
}

interface CursorResolutionOptions {
  apiKey?: string;
}

interface CursorModelOptionMatch {
  parameterId: string;
  value: string;
  canonicalToken: string;
}

interface CursorModelOptions {
  baseline: Map<string, string>;
  optionsByToken: Map<string, CursorModelOptionMatch[]>;
}

const cursorModelCatalogCache = new Map<string, Promise<CursorModelCatalog>>();

function cloneParamValues(params: ModelParameterValue[] | undefined): ModelParameterValue[] | undefined {
  return params?.map((param) => ({ ...param }));
}

function cloneModelSelection(selection: ModelSelection): ModelSelection {
  return {
    id: selection.id,
    params: cloneParamValues(selection.params),
  };
}

function serializeModelSelection(selection: ModelSelection): string {
  return JSON.stringify({
    id: selection.id,
    params: [...(selection.params ?? [])]
      .map((param) => ({ id: param.id, value: param.value }))
      .sort((a, b) => a.id.localeCompare(b.id) || a.value.localeCompare(b.value)),
  });
}

function normalizeCursorSlugPart(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const normalized = value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return normalized || undefined;
}

function getParameterValueDefinition(
  parameter: ModelParameterDefinition,
  value: string,
): { value: string; displayName?: string } | undefined {
  return parameter.values.find((entry) => entry.value === value);
}

function getCanonicalOptionToken(parameter: ModelParameterDefinition, value: string): string {
  const definition = getParameterValueDefinition(parameter, value);
  return (
    normalizeCursorSlugPart(definition?.displayName) ??
    normalizeCursorSlugPart(definition?.value) ??
    normalizeCursorSlugPart(value) ??
    value
  );
}

function getOptionLookupTokens(parameter: ModelParameterDefinition, value: string): string[] {
  const definition = getParameterValueDefinition(parameter, value);
  const tokens = new Set<string>();
  const canonical = getCanonicalOptionToken(parameter, value);
  if (canonical) tokens.add(canonical);
  const rawValue = normalizeCursorSlugPart(definition?.value ?? value);
  if (rawValue) tokens.add(rawValue);
  const displayName = normalizeCursorSlugPart(definition?.displayName);
  if (displayName) tokens.add(displayName);
  return [...tokens];
}

function buildExactModelSelection(input: string, resolvedId: string): ModelSelection {
  if (input === DEFAULT_CURSOR_MODEL) {
    return {
      id: resolvedId,
      params: cloneParamValues(DEFAULT_CURSOR_MODEL_PARAMS),
    };
  }

  return { id: resolvedId };
}

function getEffectiveDefaultParams(model: ModelListItem): ModelParameterValue[] | undefined {
  if (model.id === DEFAULT_CURSOR_MODEL) {
    return cloneParamValues(DEFAULT_CURSOR_MODEL_PARAMS);
  }

  const defaultVariant = model.variants?.find((variant) => variant.isDefault) ?? model.variants?.[0];
  return cloneParamValues(defaultVariant?.params);
}

function parseContextWindowSize(value: string): number | undefined {
  const match = value.trim().toLowerCase().match(/^(\d+(?:\.\d+)?)(k|m|g)$/);
  if (!match) return undefined;
  const amount = Number(match[1]);
  if (!Number.isFinite(amount)) return undefined;
  const multiplier = match[2] === "k" ? 1_000 : match[2] === "m" ? 1_000_000 : 1_000_000_000;
  return amount * multiplier;
}

function pickConservativeParameterValue(
  parameter: ModelParameterDefinition,
  defaultValue: string | undefined,
): string | undefined {
  if (parameter.id === "fast" && parameter.values.some((entry) => entry.value === "false")) {
    return "false";
  }

  if (parameter.id === "context") {
    const sizedValues = parameter.values
      .map((entry) => ({
        value: entry.value,
        size: parseContextWindowSize(entry.value),
      }))
      .filter((entry): entry is { value: string; size: number } => entry.size !== undefined)
      .sort((a, b) => a.size - b.size);
    if (sizedValues.length > 0) {
      return sizedValues[0].value;
    }
  }

  return defaultValue ?? (parameter.values.length === 1 ? parameter.values[0].value : undefined);
}

function buildParamMap(params: ModelParameterValue[] | undefined): Map<string, string> {
  return new Map((params ?? []).map((param) => [param.id, param.value]));
}

function buildOrderedParams(
  model: ModelListItem,
  valuesById: Map<string, string>,
): ModelParameterValue[] {
  const ordered: ModelParameterValue[] = [];
  const seen = new Set<string>();

  for (const parameter of model.parameters ?? []) {
    const value = valuesById.get(parameter.id);
    if (value === undefined) continue;
    ordered.push({ id: parameter.id, value });
    seen.add(parameter.id);
  }

  for (const [id, value] of valuesById) {
    if (seen.has(id)) continue;
    ordered.push({ id, value });
  }

  return ordered;
}

function buildConservativeBaselineParams(model: ModelListItem): Map<string, string> {
  const baseline = buildParamMap(getEffectiveDefaultParams(model));

  for (const parameter of model.parameters ?? []) {
    const preferredValue = pickConservativeParameterValue(parameter, baseline.get(parameter.id));
    if (preferredValue !== undefined) {
      baseline.set(parameter.id, preferredValue);
    }
  }

  return baseline;
}

function scoreVariantAgainstBaseline(
  variant: { params: ModelParameterValue[] },
  baseline: Map<string, string>,
  requestedParamIds: Set<string>,
): number {
  const variantById = buildParamMap(variant.params);
  const keys = new Set([...baseline.keys(), ...variantById.keys()]);
  let score = 0;

  for (const key of keys) {
    if (requestedParamIds.has(key)) continue;
    if (variantById.get(key) !== baseline.get(key)) {
      score++;
    }
  }

  return score;
}

function buildRequestedSelection(
  model: ModelListItem,
  baseline: Map<string, string>,
  requestedParams: Map<string, string>,
): ModelSelection {
  const requestedBaseline = new Map(baseline);
  for (const [id, value] of requestedParams) {
    requestedBaseline.set(id, value);
  }
  const requestedParamIds = new Set(requestedParams.keys());

  const matchingVariants = (model.variants ?? [])
    .filter((variant) =>
      [...requestedParams].every(([requestedId, requestedValue]) =>
        variant.params.some((param) => param.id === requestedId && param.value === requestedValue),
      ),
    )
    .sort((a, b) => {
      const scoreDiff =
        scoreVariantAgainstBaseline(a, requestedBaseline, requestedParamIds) -
        scoreVariantAgainstBaseline(b, requestedBaseline, requestedParamIds);
      if (scoreDiff !== 0) return scoreDiff;
      return a.params.length - b.params.length;
    });

  if (matchingVariants.length > 0) {
    return {
      id: model.id,
      params: cloneParamValues(matchingVariants[0].params),
    };
  }

  return {
    id: model.id,
    params: buildOrderedParams(model, requestedBaseline),
  };
}

function buildParameterSlugSelection(
  model: ModelListItem,
  baseline: Map<string, string>,
  requestedParam: ModelParameterValue,
): ModelSelection {
  return buildRequestedSelection(
    model,
    baseline,
    new Map([[requestedParam.id, requestedParam.value]]),
  );
}

function addSelectionCandidate(
  candidates: Map<string, Map<string, ModelSelection>>,
  slug: string,
  selection: ModelSelection,
): void {
  let bySelectionKey = candidates.get(slug);
  if (!bySelectionKey) {
    bySelectionKey = new Map<string, ModelSelection>();
    candidates.set(slug, bySelectionKey);
  }
  bySelectionKey.set(serializeModelSelection(selection), cloneModelSelection(selection));
}

function addSlugSelection(
  candidates: Map<string, Map<string, ModelSelection>>,
  supportedSlugs: Map<string, Set<string>>,
  modelId: string,
  optionTokens: string[],
  canonicalOption: string,
  selection: ModelSelection,
): void {
  const displaySlug = `${modelId}-${canonicalOption}`;
  let supported = supportedSlugs.get(modelId);
  if (!supported) {
    supported = new Set<string>();
    supportedSlugs.set(modelId, supported);
  }
  supported.add(displaySlug);

  for (const token of optionTokens) {
    addSelectionCandidate(candidates, `${modelId}-${token}`, selection);
  }
}

function addOptionMatch(
  optionsByToken: Map<string, CursorModelOptionMatch[]>,
  token: string,
  match: CursorModelOptionMatch,
): void {
  const existing = optionsByToken.get(token);
  if (existing) {
    existing.push(match);
  } else {
    optionsByToken.set(token, [match]);
  }
}

function buildCursorModelOptions(model: ModelListItem): CursorModelOptions {
  const baseline = buildConservativeBaselineParams(model);
  const optionsByToken = new Map<string, CursorModelOptionMatch[]>();

  for (const parameter of model.parameters ?? []) {
    for (const value of parameter.values) {
      const canonicalToken = getCanonicalOptionToken(parameter, value.value);
      const match: CursorModelOptionMatch = {
        parameterId: parameter.id,
        value: value.value,
        canonicalToken,
      };
      for (const token of getOptionLookupTokens(parameter, value.value)) {
        addOptionMatch(optionsByToken, token, match);
      }
    }
  }

  return {
    baseline,
    optionsByToken,
  };
}

function addParameterSlugSelections(
  model: ModelListItem,
  candidates: Map<string, Map<string, ModelSelection>>,
  supportedSlugs: Map<string, Set<string>>,
): void {
  const baseline = buildConservativeBaselineParams(model);

  for (const parameter of model.parameters ?? []) {
    for (const value of parameter.values) {
      const optionTokens = getOptionLookupTokens(parameter, value.value);
      const canonicalOption = getCanonicalOptionToken(parameter, value.value);

      addSlugSelection(
        candidates,
        supportedSlugs,
        model.id,
        optionTokens,
        canonicalOption,
        buildParameterSlugSelection(model, baseline, {
          id: parameter.id,
          value: value.value,
        }),
      );
    }
  }
}

function buildCursorModelCatalog(models: ModelListItem[]): CursorModelCatalog {
  const modelsById = new Map<string, ModelListItem>();
  const aliasCandidates = new Map<string, Set<string>>();
  const slugCandidates = new Map<string, Map<string, ModelSelection>>();
  const supportedSlugSets = new Map<string, Set<string>>();
  const modelOptionsById = new Map<string, CursorModelOptions>();

  for (const model of models) {
    modelsById.set(model.id, model);
    modelOptionsById.set(model.id, buildCursorModelOptions(model));
  }

  for (const model of models) {
    for (const alias of model.aliases ?? []) {
      let ids = aliasCandidates.get(alias);
      if (!ids) {
        ids = new Set<string>();
        aliasCandidates.set(alias, ids);
      }
      ids.add(model.id);
    }

    addParameterSlugSelections(model, slugCandidates, supportedSlugSets);
  }

  const aliasesToId = new Map<string, string>();
  const ambiguousAliases = new Map<string, string[]>();
  for (const [alias, ids] of aliasCandidates) {
    const matches = [...ids].sort();
    if (matches.length === 1) aliasesToId.set(alias, matches[0]);
    else ambiguousAliases.set(alias, matches);
  }

  const slugsToSelection = new Map<string, ModelSelection>();
  const ambiguousSlugs = new Map<string, ModelSelection[]>();
  for (const [slug, selectionsByKey] of slugCandidates) {
    const matches = [...selectionsByKey.values()];
    if (matches.length === 1) {
      slugsToSelection.set(slug, matches[0]);
    } else {
      ambiguousSlugs.set(slug, matches);
    }
  }

  const supportedSlugsByModelId = new Map<string, string[]>();
  for (const [modelId, slugs] of supportedSlugSets) {
    supportedSlugsByModelId.set(modelId, [...slugs].sort());
  }

  const supportedOptionsByModelId = new Map<string, string[]>();
  for (const [modelId, options] of modelOptionsById) {
    supportedOptionsByModelId.set(
      modelId,
      [...new Set([...options.optionsByToken.values()].flat().map((match) => match.canonicalToken))].sort(),
    );
  }

  return {
    modelsById,
    aliasesToId,
    ambiguousAliases,
    slugsToSelection,
    ambiguousSlugs,
    supportedSlugsByModelId,
    modelOptionsById,
    supportedOptionsByModelId,
  };
}

export async function loadCursorModelCatalog(
  apiKey = process.env.CURSOR_API_KEY,
): Promise<CursorModelCatalog> {
  const cacheKey = apiKey ?? DEFAULT_CATALOG_CACHE_KEY;
  const cached = cursorModelCatalogCache.get(cacheKey);
  if (cached) return cached;

  const pending = Cursor.models
    .list({ apiKey })
    .then((models) => buildCursorModelCatalog(models))
    .catch((error) => {
      cursorModelCatalogCache.delete(cacheKey);
      throw error;
    });

  cursorModelCatalogCache.set(cacheKey, pending);
  return pending;
}

export function splitCursorVariantSuffix(
  model: string,
): { baseModel: string; option: string } | undefined {
  const lastDash = model.lastIndexOf("-");
  if (lastDash <= 0 || lastDash === model.length - 1) return undefined;
  return {
    baseModel: model.slice(0, lastDash),
    option: model.slice(lastDash + 1),
  };
}

function splitCursorSlugSegments(value: string): string[] {
  return value.split("-").filter(Boolean);
}

function findCursorBaseModelCandidates(
  input: string,
  catalog: CursorModelCatalog,
): Array<{ baseInput: string; modelId: string; suffix: string }> {
  const modelCandidates = [...catalog.modelsById.keys()]
    .filter((id) => input.startsWith(`${id}-`))
    .sort((a, b) => b.length - a.length)
    .map((id) => ({
      baseInput: id,
      modelId: id,
      suffix: input.slice(id.length + 1),
    }));

  if (modelCandidates.length > 0) return modelCandidates;

  return [...catalog.aliasesToId.entries()]
    .filter(([alias]) => input.startsWith(`${alias}-`))
    .sort((a, b) => b[0].length - a[0].length)
    .map(([alias, modelId]) => ({
      baseInput: alias,
      modelId,
      suffix: input.slice(alias.length + 1),
    }));
}

function parseCursorOptionTokenizations(
  segments: string[],
  optionsByToken: Map<string, CursorModelOptionMatch[]>,
  offset = 0,
): CursorModelOptionMatch[][] {
  if (offset >= segments.length) return [[]];

  const results: CursorModelOptionMatch[][] = [];

  for (let end = offset + 1; end <= segments.length; end++) {
    const token = segments.slice(offset, end).join("-");
    const matches = optionsByToken.get(token);
    if (!matches?.length) continue;

    const tails = parseCursorOptionTokenizations(segments, optionsByToken, end);
    for (const match of matches) {
      for (const tail of tails) {
        results.push([match, ...tail]);
      }
    }
  }

  return results;
}

function resolveCursorCompoundSlugCandidates(
  input: string,
  catalog: CursorModelCatalog,
): ModelSelection[] {
  const selections = new Map<string, ModelSelection>();

  for (const candidate of findCursorBaseModelCandidates(input, catalog)) {
    const model = catalog.modelsById.get(candidate.modelId);
    const options = catalog.modelOptionsById.get(candidate.modelId);
    if (!model || !options) continue;

    const tokenizations = parseCursorOptionTokenizations(
      splitCursorSlugSegments(candidate.suffix),
      options.optionsByToken,
    );

    for (const tokenization of tokenizations) {
      const requestedParams = new Map<string, string>();
      let valid = true;

      for (const match of tokenization) {
        const existing = requestedParams.get(match.parameterId);
        if (existing && existing !== match.value) {
          valid = false;
          break;
        }
        requestedParams.set(match.parameterId, match.value);
      }

      if (!valid || requestedParams.size === 0) continue;

      const selection = buildRequestedSelection(model, options.baseline, requestedParams);
      selections.set(serializeModelSelection(selection), selection);
    }
  }

  return [...selections.values()];
}

function formatSelectionParams(selection: ModelSelection): string {
  if (!selection.params?.length) return selection.id;
  return `${selection.id} ${selection.params.map((param) => `${param.id}=${param.value}`).join(", ")}`;
}

export function formatCursorModelResolutionError(
  input: string,
  catalog: CursorModelCatalog,
): string {
  const ambiguousAlias = catalog.ambiguousAliases.get(input);
  if (ambiguousAlias) {
    return `Cursor model alias \`${input}\` is ambiguous for this account: ${ambiguousAlias
      .map((id) => `\`${id}\``)
      .join(", ")}. Use an explicit model id instead.`;
  }

  const ambiguousSlug = catalog.ambiguousSlugs.get(input);
  if (ambiguousSlug) {
    return `Cursor variant slug \`${input}\` is ambiguous for this account: ${ambiguousSlug
      .map((selection) => `\`${formatSelectionParams(selection)}\``)
      .join(", ")}. Use a raw Cursor model id instead.`;
  }

  const split = splitCursorVariantSuffix(input);
  if (split) {
    const baseCandidate = findCursorBaseModelCandidates(input, catalog)[0];
    const baseId = baseCandidate?.modelId;
    if (baseId) {
      const supportedOptions = catalog.supportedOptionsByModelId.get(baseId) ?? [];
      if (supportedOptions.length > 0) {
        return `Unknown Cursor variant slug \`${input}\`. Supported options for \`${baseId}\`: ${supportedOptions
          .map((option) => `\`${option}\``)
          .join(", ")}. You can combine multiple options with \`-\`, for example \`${baseId}-high-1m\`.`;
      }

      return `Unknown Cursor variant slug \`${input}\`. \`${baseId}\` does not expose friendly suffix slugs for this account. Use a raw Cursor model id or alias instead.`;
    }
  }

  const knownIds = [...catalog.modelsById.keys()].sort();
  const preview = knownIds.slice(0, 8).map((id) => `\`${id}\``).join(", ");
  const suffix = knownIds.length > 8 ? ", ..." : "";
  return `Unknown Cursor model or variant \`${input}\`. Use a Cursor model id, alias, or supported suffix slug from your account catalog (via \`Cursor.models.list()\`). Examples on this account: ${preview}${suffix}.`;
}

export async function resolveCursorModelSelection(
  model: string,
  options: CursorResolutionOptions = {},
): Promise<ModelSelection> {
  const catalog = await loadCursorModelCatalog(options.apiKey);

  if (catalog.modelsById.has(model)) {
    return buildExactModelSelection(model, model);
  }

  const aliasId = catalog.aliasesToId.get(model);
  if (aliasId) {
    return { id: aliasId };
  }

  const slugSelection = catalog.slugsToSelection.get(model);
  if (slugSelection) {
    return cloneModelSelection(slugSelection);
  }

  const compoundSelections = resolveCursorCompoundSlugCandidates(model, catalog);
  if (compoundSelections.length === 1) {
    return cloneModelSelection(compoundSelections[0]);
  }
  if (compoundSelections.length > 1) {
    throw new Error(
      `Cursor variant slug \`${model}\` is ambiguous for this account: ${compoundSelections
        .map((selection) => `\`${formatSelectionParams(selection)}\``)
        .join(", ")}. Use a raw Cursor model id instead.`,
    );
  }

  throw new Error(formatCursorModelResolutionError(model, catalog));
}

export function __resetCursorModelCatalogCacheForTests(): void {
  cursorModelCatalogCache.clear();
}

export function buildCursorReadOnlyPreamble(projectRoot: string): string {
  return `## Environment

You are running inside the Cursor SDK in local read-only mode.

- **Project root**: \`${projectRoot}\`
- **Use Cursor read tools** like \`ReadFile\`, \`Glob\`, \`rg\`, and other non-mutating inspection tools to understand the code.
- **Do not edit files** or change the repository. This is a static-analysis task only.
- **Do not use \`CreatePlan\` or any planning tool.** This is not an implementation task.
- **Output**: reply with exactly one fenced \`\`\`json ... \`\`\` block matching the requested schema, with no prose before or after it.`;
}
