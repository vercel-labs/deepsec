"use client";

import { useState } from "react";

export function RunCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="flex items-center gap-3 border border-gray-alpha-400 bg-background-200 py-3 pl-4 pr-2">
      <p className="flex min-w-0 items-baseline gap-3 font-mono text-sm text-gray-1000">
        <span className="select-none text-gray-800">Run</span>
        <span className="truncate">{command}</span>
      </p>
      <button
        type="button"
        onClick={copy}
        aria-label="Copy command"
        className="ml-auto flex shrink-0 items-center gap-1.5 px-2 py-1 text-sm text-gray-900 transition-colors hover:text-gray-1000"
      >
        {copied ? (
          <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path
              d="M13.5 4.5L6 12L2.5 8.5"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        ) : (
          <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none">
            <rect
              x="5.5"
              y="5.5"
              width="8"
              height="8"
              rx="1"
              stroke="currentColor"
              strokeWidth="1.5"
            />
            <path
              d="M10.5 3.5V3a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 3v5A1.5 1.5 0 0 0 4 9.5h.5"
              stroke="currentColor"
              strokeWidth="1.5"
            />
          </svg>
        )}
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}
