import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";

/**
 * Detects event handler dispatch tables where handler names
 * don't match event names — potential copy-paste bugs.
 * Found a real bug: dsync.group.user_removed calling dsyncGroupUserAdded.
 */
export const eventHandlerMismatchMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "event-handler-mismatch",
  description: "Event handlers where function name contradicts event name",
  filePatterns: [
    "**/event-consumer*.{ts,js}",
    "**/handler*.{ts,js}",
    "**/subscriber*.{ts,js}",
    "**/consumer*.{ts,js}",
    "**/dispatch*.{ts,js}",
    "**/listener*.{ts,js}",
    "**/webhook*.{ts,js}",
    "**/*.{ts,js}",
  ],
  examples: [
    `switch (event.type) {
  case "user.removed":
    return userAdded(event.payload);
  case "user.added":
    return userRemoved(event.payload);
}`,
    `switch (event) {
  case "team.deleted":
    return createTeam(event.id);
}`,
    `switch (eventType) {
  case "membership.added":
    return removeMembership(id);
}`,
    `switch (event.type) {
  case "post.created":
    return deletePost(post.id);
}`,
    `switch (event.kind) {
  case "record.updated":
    return createRecord(input);
}`,
  ],
  match(content, filePath) {
    if (/\.(test|spec|mock|stub)\./i.test(filePath)) return [];
    if (/node_modules|\.next|dist\//.test(filePath)) return [];

    // Only look at files with event dispatch patterns
    if (!/switch\s*\(.*event|case\s+['"].*\.(created|updated|deleted|removed|added)/i.test(content))
      return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    // Track case labels and the functions called within
    const opposites: Record<string, string[]> = {
      removed: ["add", "create", "insert", "Added"],
      deleted: ["add", "create", "insert", "Added"],
      added: ["remove", "delete", "destroy", "Removed", "Deleted"],
      created: ["remove", "delete", "destroy", "Removed", "Deleted"],
      updated: ["create", "delete", "Created", "Deleted"],
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const caseMatch = line.match(/case\s+['"]([\w.]+)['"]/);
      if (!caseMatch) continue;

      const eventName = caseMatch[1].toLowerCase();
      // Find which action this event implies
      let eventAction: string | null = null;
      for (const action of Object.keys(opposites)) {
        if (eventName.includes(action)) {
          eventAction = action;
          break;
        }
      }
      if (!eventAction) continue;

      // Look at the next 5 lines for function calls
      const window = lines.slice(i + 1, Math.min(lines.length, i + 6)).join("\n");
      const wrongPatterns = opposites[eventAction];
      for (const wrong of wrongPatterns) {
        const regex = new RegExp(`\\b\\w*${wrong}\\w*\\s*\\(`, "i");
        if (regex.test(window)) {
          const start = Math.max(0, i - 1);
          const end = Math.min(lines.length, i + 6);
          matches.push({
            vulnSlug: "event-handler-mismatch",
            lineNumbers: [i + 1],
            snippet: lines.slice(start, end).join("\n"),
            matchedPattern: `Event "${caseMatch[1]}" calls function matching "${wrong}" — possible copy-paste bug`,
          });
          break;
        }
      }
    }

    return matches;
  },
};
