import { createMdxComponents } from "@vercel/geistdocs/mdx";
import type { MDXComponents } from "mdx/types";

export const getMDXComponents = (components?: MDXComponents): MDXComponents =>
  createMdxComponents(components);
