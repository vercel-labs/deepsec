import { createSource } from "@vercel/geistdocs/source";
import { docs } from "@/.source/server";
import { config } from "./config";

export const geistdocsSource = createSource({
  docs,
  config,
});

export const source = geistdocsSource.source;
