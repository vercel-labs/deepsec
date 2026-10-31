import { Feed } from "feed";
import { config } from "@/lib/geistdocs/config";
import { source } from "@/lib/geistdocs/source";

const protocol = process.env.NODE_ENV === "production" ? "https" : "http";
const baseUrl = `${protocol}://${process.env.NEXT_PUBLIC_VERCEL_PROJECT_PRODUCTION_URL ?? "localhost:3000"}`;

export const revalidate = false;

export const GET = () => {
  const feed = new Feed({
    title: config.title,
    id: baseUrl,
    link: baseUrl,
    language: "en",
    copyright: `All rights reserved ${new Date().getFullYear()}, Vercel`,
  });

  for (const page of source.getPages("en")) {
    const data = page.data as {
      description?: string;
      lastModified?: Date;
      title?: string;
    };

    feed.addItem({
      id: page.url,
      title: data.title ?? page.url,
      description: data.description,
      link: `${baseUrl}${page.url}`,
      date: new Date(data.lastModified ?? new Date()),
      author: [
        {
          name: "Vercel",
        },
      ],
    });
  }

  return new Response(feed.rss2(), {
    headers: {
      "Content-Type": "application/rss+xml",
    },
  });
};
