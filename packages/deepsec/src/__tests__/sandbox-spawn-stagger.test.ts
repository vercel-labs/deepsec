import { APIError } from "@vercel/sandbox";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  spawned: [] as number[],
  dispatched: [] as number[],
  commands: [] as Array<{ cmd: string; args: string[] }>,
  saved: [] as string[],
  releases: new Map<string, () => void>(),
  goneMode: false,
  exitCode: 0,
  stderr: "",
  failDispatch: -1,
  stops: 0,
  downloads: 0,
  logs: [] as string[],
}));

const gone = () =>
  new APIError(new Response(null, { status: 410 }), { message: "Status code 410 is not ok" });

vi.mock("../sandbox/partitioner.js", () => ({
  partitionFiles: () => ({ partitions: [["a.ts"], ["b.ts"], ["c.ts"]], totalFiles: 3 }),
}));

vi.mock("../sandbox/download.js", () => ({
  downloadResults: async () => {
    h.downloads++;
    if (h.goneMode) throw gone();
    return 0;
  },
}));

vi.mock("../sandbox/state.js", async (orig) => ({
  ...(await orig<typeof import("../sandbox/state.js")>()),
  saveRunState: (s: { sandboxes: unknown[]; reserved?: unknown[] }) =>
    h.saved.push(`${s.sandboxes.length}/${s.reserved?.length ?? 0}`),
  updateRunState: (s: { sandboxes: unknown[]; reserved?: unknown[] }) =>
    h.saved.push(`${s.sandboxes.length}/${s.reserved?.length ?? 0}`),
  deleteRunState: () => h.saved.push("deleted"),
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
        if (h.goneMode) throw gone();
        await done;
      },
      wait: async () => {
        if (h.goneMode) throw gone();
        await done;
        return {
          exitCode: h.exitCode,
          async *logs() {
            if (h.stderr) yield { stream: "stderr", data: h.stderr };
          },
        };
      },
    };
    return {
      sandboxId: id,
      writeFiles: async () => {},
      runCommand: async (c: { cmd: string; args: string[] }) => {
        if (h.dispatched.length === h.failDispatch) {
          h.failDispatch = -1;
          throw new Error("dispatch failed");
        }
        h.dispatched.push(Date.now());
        h.commands.push({ cmd: c.cmd, args: c.args });
        return cmd;
      },
      getCommand: async () => {
        if (h.goneMode) throw gone();
        return { ...cmd, exitCode: h.exitCode === 0 ? null : h.exitCode };
      },
      stop: async () => {
        h.stops++;
      },
    };
  },
}));

const { createSpawnLimiter, launch, orchestrate, spawnDelays } = await import(
  "../sandbox/orchestrator.js"
);

function reset() {
  Object.assign(h, {
    spawned: [],
    dispatched: [],
    commands: [],
    saved: [],
    goneMode: false,
    exitCode: 0,
    stderr: "",
    failDispatch: -1,
    stops: 0,
    downloads: 0,
    logs: [],
  });
  h.releases.clear();
}

const baseConfig = {
  projectId: "p",
  command: "process" as const,
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
  extraArgs: [],
};

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
    // Reserved at partitioning, then moved over as each worker dispatches.
    expect(h.saved).toEqual(["0/3", "1/2"]);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawned.length).toBe(2);
    expect(h.dispatched.length).toBe(2);
    expect(h.saved).toEqual(["0/3", "1/2", "2/1"]);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawned.map((t) => Math.round((t - t0) / 1000))).toEqual([0, 60, 120]);
    expect(h.saved).toEqual(["0/3", "1/2", "2/1", "3/0"]);
    // Each process worker gets its own run ID for its file locks.
    for (const c of h.commands) {
      expect(c.cmd).toBe("env");
      expect(c.args[0]).toMatch(/^DEEPSEC_WORKER_RUN_ID=\d{14}-[0-9a-f]{16}$/);
    }

    for (const release of h.releases.values()) release();
    await vi.advanceTimersByTimeAsync(30_000);
    const results = await run;
    expect(results.map((r) => r.success)).toEqual([true, true, true]);
    expect(h.saved.at(-1)).toBe("deleted");
  });

  it("treats a sandbox that times out mid-run as gone: no stop, no 'left for collect'", async () => {
    vi.useRealTimers();
    reset();
    h.goneMode = true;
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

  it("doesn't treat a failed worker as gone because of what it printed", async () => {
    vi.useRealTimers();
    reset();
    h.exitCode = 1;
    h.stderr = "sandbox_stopped: Status code 410 is not ok; no longer available";
    const run = orchestrate({ ...baseConfig, sandboxCount: 1, spawnRate: 0 }, (m) =>
      h.logs.push(m),
    );
    // The partitioner mock always yields three partitions.
    await vi.waitFor(() => expect(h.releases.size).toBe(3));
    for (const release of h.releases.values()) release();
    const results = await run;
    expect(results.map((r) => r.success)).toEqual([false, false, false]);
    // Results are still downloaded and the sandboxes are stopped as usual.
    expect(h.downloads).toBeGreaterThanOrEqual(3);
    expect(h.stops).toBe(3);
    expect(h.logs.some((l) => /Sandbox is gone/.test(l))).toBe(false);
  });
});

describe("launch (detached)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("saves each dispatch as it happens and drops a partition that failed to dispatch", async () => {
    reset();
    h.failDispatch = 1;
    await launch({ ...baseConfig, sandboxCount: 3, spawnRate: 0 }, (m) => h.logs.push(m));
    expect(h.saved).toEqual(["0/3", "1/2", "1/1", "2/0"]);
    expect(h.logs.some((l) => /\[sandbox-1\] Dispatch failed: dispatch failed/.test(l))).toBe(true);
    expect(h.logs.some((l) => /launched with 2 sandbox\(es\)/.test(l))).toBe(true);
  });
});

describe("createSpawnLimiter", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("spaces starts across callers and doesn't burst for a late caller", async () => {
    vi.useFakeTimers();
    const t0 = Date.now();
    const limiter = createSpawnLimiter(10, () => 0);
    const started: number[] = [];
    const take = () =>
      limiter.next().then(() => started.push(Math.round((Date.now() - t0) / 1000)));
    // Two projects ask for slots at the same time.
    const first = [take(), take(), take()];
    await vi.advanceTimersByTimeAsync(20_000);
    await Promise.all(first);
    expect(started).toEqual([0, 6, 12]);
    // A third project finishes bootstrapping much later: its sandboxes
    // start from now on, one slot apart, not all at once.
    await vi.advanceTimersByTimeAsync(100_000);
    const late = [take(), take()];
    await vi.advanceTimersByTimeAsync(10_000);
    await Promise.all(late);
    expect(started.slice(3)).toEqual([120, 126]);
  });
});
