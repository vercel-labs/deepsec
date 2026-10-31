import {
  defineGeistdocsSourceConfig,
  geistdocsFrontmatterSchema,
  geistdocsMetaSchema,
} from "@vercel/geistdocs/source-config";
import { defineDocs } from "fumadocs-mdx/config";

// The docs live at the repository root so they stay readable on GitHub;
// the website compiles them in place.
export const docs = defineDocs({
  dir: "../../docs",
  docs: {
    schema: geistdocsFrontmatterSchema,
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: geistdocsMetaSchema,
  },
});

export default defineGeistdocsSourceConfig();
