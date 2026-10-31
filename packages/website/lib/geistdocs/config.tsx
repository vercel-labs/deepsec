import { defineConfig } from "@vercel/geistdocs/config";
import type { ReactNode } from "react";

export const github = {
  owner: "vercel-labs",
  repo: "deepsec",
  branch: "main",
  editPath: "docs/{path}",
};

const nav = [
  {
    label: "Docs",
    href: "/docs",
  },
  {
    label: "GitHub",
    href: `https://github.com/${github.owner}/${github.repo}`,
    external: true,
  },
];

const suggestions = [
  "How do I run my first deepsec scan?",
  "How does deepsec resume interrupted runs?",
  "How do I review only PR changes?",
  "How do custom matchers work?",
];

function DeepsecLogo({ mark = true }: { mark?: boolean }) {
  return (
    <span className="flex items-center gap-2 text-gray-1000">
      {mark ? (
        <span className="grid size-6 place-items-center border border-gray-1000 bg-gray-1000 text-[10px] font-bold text-background-100">
          ds
        </span>
      ) : null}
      <span className="font-semibold text-sm">deepsec</span>
    </span>
  );
}

const logo: ReactNode = <DeepsecLogo />;

export const config = defineConfig({
  title: "deepsec Documentation",
  logo,
  nav,
  navbarVariant: "oss",
  github,
  search: {
    enabled: true,
  },
  ai: {
    enabled: false,
    suggestions,
  },
  agent: {
    enabled: false,
    product: {
      name: "deepsec",
      description:
        "A full-repository security review tool that gives coding agents source access, project context, resumable state, and CI review modes.",
      category: "Application security",
      audience: ["application security teams", "platform engineers"],
      useCases: [
        "Run source-aware full-repository security reviews",
        "Review changed files in CI for net-new findings",
        "Write project-specific matchers for internal frameworks",
      ],
    },
  },
  translations: {
    en: {
      displayName: "English",
    },
  },
});
