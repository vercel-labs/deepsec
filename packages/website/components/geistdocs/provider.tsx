"use client";

import { GeistdocsProvider as PackageProvider } from "@vercel/geistdocs/layout";
import type { ComponentProps } from "react";
import { config } from "@/lib/geistdocs/config";

type GeistdocsProviderProps = Omit<ComponentProps<typeof PackageProvider>, "config">;

export const GeistdocsProvider = (props: GeistdocsProviderProps) => (
  <PackageProvider config={config} {...props} />
);
