import { MobileDocsBar } from "@vercel/geistdocs/mobile-docs-bar";
import { createDocsPage } from "@vercel/geistdocs/pages/docs";
import type { ComponentProps, ElementType } from "react";
import { getMDXComponents } from "@/components/geistdocs/mdx-components";
import { config, github } from "@/lib/geistdocs/config";
import { geistdocsSource } from "@/lib/geistdocs/source";

// The docs are plain markdown that also gets read on GitHub, so they
// cross-link with relative `.md` paths. Rewrite sibling links to doc routes
// and links that escape docs/ (e.g. ../SECURITY.md) to the GitHub blob view.
function resolveDocHref(href: string | undefined) {
  if (!href || !/\.md(#|$)/.test(href) || /^[a-z]+:/.test(href)) {
    return href;
  }

  const [path, hash] = href.split("#");
  const suffix = hash ? `#${hash}` : "";

  if (path.startsWith("../")) {
    return `https://github.com/${github.owner}/${github.repo}/blob/main/${path.replace(/^(\.\.\/)+/, "")}${suffix}`;
  }

  return `/docs/${path.replace(/^\.\//, "").replace(/\.md$/, "")}${suffix}`;
}

const docsPage = createDocsPage({
  config,
  mdx: ({ link }) => {
    const DocsLink = (link ?? "a") as ElementType;
    return getMDXComponents({
      a: (props: ComponentProps<"a">) => <DocsLink {...props} href={resolveDocHref(props.href)} />,
    });
  },
  source: geistdocsSource,
  tableOfContentPopover: {
    enabled: false,
  },
  renderTop: ({ data }) => <MobileDocsBar toc={data.toc} />,
});

// The site is English-only and serves docs at /docs/<slug> without a locale
// segment (hideLocale: "default-locale"), so pin lang instead of routing it.
type PageParams = { slug: string[] };

export default function Page({ params }: { params: Promise<PageParams> }) {
  return docsPage.Page({
    params: params.then(({ slug }) => ({ lang: "en", slug })),
  });
}

export function generateStaticParams() {
  return docsPage
    .generateStaticParams()
    .filter((param) => param.lang === "en" && param.slug?.length)
    .map(({ slug }) => ({ slug: slug as string[] }));
}

export function generateMetadata({ params }: { params: Promise<PageParams> }) {
  return docsPage.generateMetadata({
    params: params.then(({ slug }) => ({ lang: "en", slug })),
  });
}
