import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  spawned: [] as number[],
  dispatched: [] as number[],
  saved: [] as number[],
  releases: new Map<string, () => void>(),
  goneMode: false,
  stops: 0,
  downloads: 0,
  logs: [] as string[],
}));

vi.mock("../sandbox/partitioner.js", () => ({
  partitionFiles: () => ({ partitions: [["a.ts"], ["b.ts"], ["c.ts"]], totalFiles: 3 }),
}));

vi.mock("../sandbox/download.js", () => ({
  downloadResults: async () => {
    h.downloads++;
    if (h.goneMode) throw new Error("Status code 410 is not ok");
    return 0;
  },
}));

vi.mock("../sandbox/state.js", async (orig) => ({
  ...(await orig<typeof import("../sandbox/state.js")>()),
  saveRunState: (s: { sandboxes: unknown[] }) => h.saved.push(s.sandboxes.length),
  updateRunState: (s: { sandboxes: unknown[] }) => h.saved.push(s.sandboxes.length),
  deleteRunState: () => {},
}));

vi.mock("../sandbox/setup.js", async (orig) => ({
  ...(await orig<typeof import("../sandbox/setup.js")>()),
  spawnFromSnapshot: async () => {
    const id = `sbx_${h.spawned.length}`;
    h.spawned.push(Date.now());
    let release!: () => void;
    const done = new Promise<void>((r) => {
      release = r;
    });
    h.releases.set(id, release);
    const cmd = {
      cmdId: `cmd_${id}`,
      exitCode: null as number | null,
      async *logs() {
        if (h.goneMode) throw new Error("Status code 410 is not ok");
        await done;
      },
      wait: async () => {
        if (h.goneMode) throw new Error("Status code 410 is not ok");
        await done;
        return { exitCode: 0, async *logs() {} };
      },
    };
    return {
      sandboxId: id,
      writeFiles: async () => {},
      runCommand: async () => {
        h.dispatched.push(Date.now());
        return cmd;
      },
      getCommand: async () => {
        if (h.goneMode) throw new Error("Status code 410 is not ok");
        return cmd;
      },
      stop: async () => {
        h.stops++;
      },
    };
  },
}));

const { orchestrate, spawnDelays } = await import("../sandbox/orchestrator.js");

describe("spawnDelays", () => {
  it("starts small runs at once and staggers big ones within per-slot jitter", () => {
    expect(spawnDelays(10, 10)).toEqual(new Array(10).fill(0));
    expect(spawnDelays(50, 0)).toEqual(new Array(50).fill(0));
    const d = spawnDelays(100, 10);
    d.forEach((ms, i) => {
      expect(ms).toBeGreaterThanOrEqual(i * 6000);
      expect(ms).toBeLessThan((i + 1) * 6000);
    });
  });

  it("never puts more than rate+1 starts in any 60s window", () => {
    for (let trial = 0; trial < 20; trial++) {
      const d = spawnDelays(100, 10).sort((a, b) => a - b);
      for (const start of d) {
        expect(d.filter((t) => t >= start && t < start + 60_000).length).toBeLessThanOrEqual(11);
      }
    }
  });
});

describe("orchestrate with a spawn rate", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("dispatches each worker as soon as it's ready and grows the run state", async () => {
    const t0 = Date.now();
    const run = orchestrate(
      {
        projectId: "p",
        command: "process",
        sandboxCount: 3,
        vcpus: 2,
        concurrency: 2,
        batchSize: 5,
        agentType: "codex",
        model: "m",
        snapshotId: "snap_test",
        saveSnapshot: false,
        keepAlive: false,
        reinvestigate: false,
        force: false,
        timeout: 60_000,
        spawnRate: 1,
        extraArgs: [],
      },
      () => {},
    );

    await vi.advanceTimersByTimeAsync(1000);
    expect(h.spawned.length).toBe(1);
    expect(h.dispatched.length).toBe(1);
    expect(h.saved).toEqual([1]);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawned.length).toBe(2);
    expect(h.dispatched.length).toBe(2);
    expect(h.saved).toEqual([1, 2]);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawned.map((t) => Math.round((t - t0) / 1000))).toEqual([0, 60, 120]);
    expect(h.saved).toEqual([1, 2, 3]);

    for (const release of h.releases.values()) release();
    await vi.advanceTimersByTimeAsync(30_000);
    const results = await run;
    expect(results.map((r) => r.success)).toEqual([true, true, true]);
  });

  it("treats a sandbox that times out mid-run as gone: no stop, no 'left for collect'", async () => {
    vi.useRealTimers();
    Object.assign(h, {
      goneMode: true,
      stops: 0,
      downloads: 0,
      logs: [],
      spawned: [],
      dispatched: [],
      saved: [],
    });
    h.releases.clear();
    const results = await orchestrate(
      {
        projectId: "p",
        command: "process",
        sandboxCount: 1,
        vcpus: 2,
        concurrency: 2,
        batchSize: 5,
        agentType: "codex",
        model: "m",
        snapshotId: "snap_test",
        saveSnapshot: false,
        keepAlive: false,
        reinvestigate: false,
        force: false,
        timeout: 60_000,
        spawnRate: 0,
        extraArgs: [],
      },
      (m) => h.logs.push(m),
    );
    expect(results[0].success).toBe(false);
    expect(h.stops).toBe(0);
    expect(h.logs.some((l) => /Sandbox is gone \(timed out or stopped\)/.test(l))).toBe(true);
    expect(h.logs.some((l) => /left running so its results can be collected/i.test(l))).toBe(false);
    expect(h.logs.some((l) => /waiting for the command failed/.test(l))).toBe(false);
    h.goneMode = false;
  });
});
