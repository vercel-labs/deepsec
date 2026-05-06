import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const nonAtomicOperationMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "non-atomic-operation",
  description: "Read-then-write without transaction/lock — TOCTOU race condition risk",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `async function transfer(id) {
  const account = await db.account.findById(id);
  if (account.balance < 100) return;
  await db.account.update({ id, balance: account.balance - 100 });
}`,
    `const user = await prisma.user.findUnique({ where: { id } });
if (!user) throw new Error("missing");
await prisma.user.delete({ where: { id } });`,
    `const item = await repo.findOne({ id });
await repo.save({ ...item, count: item.count + 1 });`,
    `const row = await store.findFirst({ where: { key } });
const next = row.value + 1;
await store.update({ where: { key }, data: { value: next } });`,
    `const order = await orders.findUnique({ where: { id } });
await orders.modify({ id: order.id });`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    // Only flag files that have both a read and a write on the same resource type
    const hasReadWrite =
      /findById|getById|findOne|findUnique|findFirst/.test(content) &&
      /update|delete|remove|modify|save|create/.test(content);
    if (!hasReadWrite) return [];

    // Skip if there's a transaction wrapper
    if (/transaction\s*\(|\.transact\(|BEGIN|COMMIT|withLock|mutex|atomicUpdate/.test(content))
      return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    const readPatterns = [
      /await.*find(ById|One|Unique|First)\s*\(/,
      /await.*get\w+By(Id|Uid)\s*\(/,
    ];

    for (let i = 0; i < lines.length; i++) {
      if (!readPatterns.some((p) => p.test(lines[i]))) continue;

      // Check next 15 lines for a write on the same resource
      const window = lines.slice(i + 1, Math.min(lines.length, i + 15)).join("\n");
      if (/await.*(update|delete|remove|modify|save)\s*\(/.test(window)) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 5);
        matches.push({
          vulnSlug: "non-atomic-operation",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "Read-then-write without transaction — verify atomicity",
        });
      }
    }

    return matches;
  },
};
