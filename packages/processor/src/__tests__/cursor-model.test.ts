import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { listMock } = vi.hoisted(() => ({
  listMock: vi.fn(),
}));

vi.mock("@cursor/sdk", () => ({
  Cursor: {
    models: {
      list: listMock,
    },
  },
}));

import {
  __resetCursorModelCatalogCacheForTests,
  resolveCursorModelSelection,
} from "../agents/cursor-model.js";

const cursorCatalog = [
  {
    id: "composer-2.5",
    displayName: "Composer 2.5",
    aliases: ["composer"],
    parameters: [
      {
        id: "fast",
        displayName: "Fast",
        values: [{ value: "false" }, { value: "true", displayName: "Fast" }],
      },
    ],
    variants: [
      {
        params: [{ id: "fast", value: "true" }],
        displayName: "Composer 2.5",
        isDefault: true,
      },
      {
        params: [{ id: "fast", value: "false" }],
        displayName: "Composer 2.5",
      },
    ],
  },
  {
    id: "gpt-5.4",
    displayName: "GPT-5.4",
    aliases: ["gpt"],
    parameters: [
      {
        id: "context",
        displayName: "Context",
        values: [
          { value: "272k", displayName: "272K" },
          { value: "1m", displayName: "1M" },
        ],
      },
      {
        id: "reasoning",
        displayName: "Reasoning",
        values: [
          { value: "low", displayName: "Low" },
          { value: "medium", displayName: "Medium" },
          { value: "high", displayName: "High" },
          { value: "extra-high", displayName: "Extra High" },
        ],
      },
      {
        id: "fast",
        displayName: "Fast",
        values: [{ value: "false" }, { value: "true", displayName: "Fast" }],
      },
    ],
    variants: [
      {
        params: [
          { id: "context", value: "1m" },
          { id: "reasoning", value: "medium" },
          { id: "fast", value: "false" },
        ],
        displayName: "GPT-5.4",
        isDefault: true,
      },
      {
        params: [
          { id: "context", value: "272k" },
          { id: "reasoning", value: "high" },
          { id: "fast", value: "false" },
        ],
        displayName: "GPT-5.4",
      },
      {
        params: [
          { id: "context", value: "272k" },
          { id: "reasoning", value: "extra-high" },
          { id: "fast", value: "false" },
        ],
        displayName: "GPT-5.4",
      },
      {
        params: [
          { id: "context", value: "272k" },
          { id: "reasoning", value: "medium" },
          { id: "fast", value: "true" },
        ],
        displayName: "GPT-5.4",
      },
    ],
  },
  {
    id: "gpt-5.4-mini",
    displayName: "GPT-5.4 Mini",
    aliases: ["gpt-mini"],
    parameters: [
      {
        id: "reasoning",
        displayName: "Reasoning",
        values: [{ value: "medium", displayName: "Medium" }],
      },
    ],
    variants: [
      {
        params: [{ id: "reasoning", value: "medium" }],
        displayName: "GPT-5.4 Mini",
        isDefault: true,
      },
    ],
  },
];

describe("resolveCursorModelSelection", () => {
  beforeEach(() => {
    listMock.mockReset();
    __resetCursorModelCatalogCacheForTests();
    listMock.mockResolvedValue(cursorCatalog);
  });

  afterEach(() => {
    __resetCursorModelCatalogCacheForTests();
  });

  it("keeps composer-2.5 on the non-fast default", async () => {
    await expect(resolveCursorModelSelection("composer-2.5")).resolves.toEqual({
      id: "composer-2.5",
      params: [{ id: "fast", value: "false" }],
    });
  });

  it("passes through exact model ids", async () => {
    await expect(resolveCursorModelSelection("gpt-5.4-mini")).resolves.toEqual({
      id: "gpt-5.4-mini",
    });
  });

  it("passes through exact aliases", async () => {
    await expect(resolveCursorModelSelection("gpt")).resolves.toEqual({
      id: "gpt-5.4",
    });
  });

  it("resolves a suffix slug to the matching default-preserving variant", async () => {
    await expect(resolveCursorModelSelection("gpt-5.4-high")).resolves.toEqual({
      id: "gpt-5.4",
      params: [
        { id: "context", value: "272k" },
        { id: "reasoning", value: "high" },
        { id: "fast", value: "false" },
      ],
    });
  });

  it("accepts multiword option slugs from Cursor display names", async () => {
    await expect(resolveCursorModelSelection("gpt-5.4-extra-high")).resolves.toEqual({
      id: "gpt-5.4",
      params: [
        { id: "context", value: "272k" },
        { id: "reasoning", value: "extra-high" },
        { id: "fast", value: "false" },
      ],
    });
  });

  it("keeps large context as an explicit opt-in slug", async () => {
    await expect(resolveCursorModelSelection("gpt-5.4-1m")).resolves.toEqual({
      id: "gpt-5.4",
      params: [
        { id: "context", value: "1m" },
        { id: "reasoning", value: "medium" },
        { id: "fast", value: "false" },
      ],
    });
  });

  it("combines multiple option slugs when they target different parameters", async () => {
    await expect(resolveCursorModelSelection("gpt-5.4-high-1m")).resolves.toEqual({
      id: "gpt-5.4",
      params: [
        { id: "context", value: "1m" },
        { id: "reasoning", value: "high" },
        { id: "fast", value: "false" },
      ],
    });
  });

  it("accepts combined options in any order", async () => {
    await expect(resolveCursorModelSelection("gpt-5.4-1m-high")).resolves.toEqual({
      id: "gpt-5.4",
      params: [
        { id: "context", value: "1m" },
        { id: "reasoning", value: "high" },
        { id: "fast", value: "false" },
      ],
    });
  });

  it("lists supported suffixes for a known base model", async () => {
    await expect(resolveCursorModelSelection("gpt-5.4-ultra")).rejects.toThrow(
      /Supported options for `gpt-5\.4`:/,
    );
    await expect(resolveCursorModelSelection("gpt-5.4-ultra")).rejects.toThrow(
      /`high`/,
    );
    await expect(resolveCursorModelSelection("gpt-5.4-ultra")).rejects.toThrow(
      /`extra-high`/,
    );
  });

  it("surfaces ambiguous suffixes instead of guessing", async () => {
    listMock.mockResolvedValue([
      {
        id: "ambiguous-1.0",
        displayName: "Ambiguous 1.0",
        parameters: [
          {
            id: "reasoning",
            displayName: "Reasoning",
            values: [
              { value: "low", displayName: "Low" },
              { value: "high", displayName: "High" },
            ],
          },
          {
            id: "effort",
            displayName: "Effort",
            values: [
              { value: "low", displayName: "Low" },
              { value: "high", displayName: "High" },
            ],
          },
        ],
        variants: [
          {
            params: [
              { id: "reasoning", value: "low" },
              { id: "effort", value: "low" },
            ],
            displayName: "Ambiguous 1.0",
            isDefault: true,
          },
          {
            params: [
              { id: "reasoning", value: "high" },
              { id: "effort", value: "low" },
            ],
            displayName: "Ambiguous 1.0",
          },
          {
            params: [
              { id: "reasoning", value: "low" },
              { id: "effort", value: "high" },
            ],
            displayName: "Ambiguous 1.0",
          },
        ],
      },
    ]);
    __resetCursorModelCatalogCacheForTests();

    await expect(resolveCursorModelSelection("ambiguous-1.0-high")).rejects.toThrow(
      /Cursor variant slug `ambiguous-1\.0-high` is ambiguous/,
    );
  });

  it("caches the catalog per api key", async () => {
    await resolveCursorModelSelection("gpt-5.4-high", { apiKey: "key-1" });
    await resolveCursorModelSelection("gpt-5.4-extra-high", { apiKey: "key-1" });
    await resolveCursorModelSelection("gpt-5.4-mini", { apiKey: "key-2" });

    expect(listMock).toHaveBeenCalledTimes(2);
    expect(listMock).toHaveBeenNthCalledWith(1, { apiKey: "key-1" });
    expect(listMock).toHaveBeenNthCalledWith(2, { apiKey: "key-2" });
  });
});
