import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

export const pageDataFetchMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "page-data-fetch",
  description:
    "Server Component pages reading searchParams/params for data fetching — IDOR/SSRF risk",
  filePatterns: ["**/app/**/page.{ts,tsx}", "**/pages/**/*.{ts,tsx}"],
  requires: { tech: ["nextjs"] },
  examples: [
    `export default async function Page({ searchParams }) {\n  const id = searchParams.get('id');\n  const data = await fetch('/api/x?id=' + id);\n  return null\n}`,
    `export default async function Page({ params }) {\n  const r = await fetch('/api/users/' + params.id);\n  return null\n}`,
    `export default async function Page({ searchParams }) {\n  const q = searchParams['q'];\n  const data = await fetchApi('/search?q=' + q);\n  return null\n}`,
    `export async function getServerSideProps(ctx) {\n  const data = await fetch('/api/foo?id=' + ctx.query.id);\n  return { props: { data, query: ctx.params.id } }\n}`,
    `export async function getStaticProps(ctx) {\n  const data = await fetch('/api/items/' + ctx.params.slug);\n  return { props: { data } }\n}`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    const hasParams = /searchParams|params\.\w+/.test(content);
    const hasFetch = /fetch\(|fetchApi|getServerSideProps|getStaticProps/.test(content);
    if (!hasParams || !hasFetch) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      if (
        /searchParams\.get|searchParams\[|params\.\w+/.test(lines[i]) &&
        /fetch|Api|query/.test(lines.slice(i, Math.min(lines.length, i + 10)).join("\n"))
      ) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 4);
        matches.push({
          vulnSlug: "page-data-fetch",
          lineNumbers: [i + 1],
          snippet: lines.slice(start, end).join("\n"),
          matchedPattern: "Page reads URL params and fetches data — verify auth scoping",
        });
        break;
      }
    }

    return matches;
  },
};
