import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createMDX } from "fumadocs-mdx/next";
import type { NextConfig } from "next";

const packageRoot = dirname(fileURLToPath(import.meta.url));
// The docs collection compiles ../../docs (repo root), so Turbopack's root
// must span the whole repository, not just this package.
const repoRoot = resolve(packageRoot, "../..");

const withMDX = createMDX();

const nextConfig: NextConfig = {
  turbopack: {
    root: repoRoot,
  },
  async redirects() {
    return [
      {
        // The marketing homepage now lives on vercel.com; DeepSec's docs
        // remain on deepsec.sh. Keep this temporary during the launch soak.
        source: "/",
        has: [{ type: "host", value: "deepsec.sh" }],
        destination: "https://vercel.com/oss/deepsec",
        permanent: false,
      },
    ];
  },
};

export default withMDX(nextConfig);
