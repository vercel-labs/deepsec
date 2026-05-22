#!/usr/bin/env node

const prompt = process.argv[6] ?? "";

if (prompt.includes("MALFORMED")) {
  console.log("not json");
  process.exit(0);
}

if (prompt.includes("SLOW")) {
  setTimeout(() => {}, 60_000);
}

if (prompt.includes("## Verdicts")) {
  console.error("[fake-copilot] turns=3 session=fake-revalidate");
  console.log(`\`\`\`json
[
  {
    "filePath": "src/app.ts",
    "title": "stored xss",
    "verdict": "true-positive",
    "reasoning": "The fake delegate confirms the finding for test coverage."
  }
]
\`\`\``);
  process.exit(0);
}

console.error("[fake-copilot] turns=2 session=fake-investigate");
console.log(`\`\`\`json
[
  {
    "filePath": "src/app.ts",
    "findings": [
      {
        "severity": "HIGH",
        "vulnSlug": "xss",
        "title": "stored xss",
        "description": "The fake delegate found a stored XSS issue.",
        "lineNumbers": [7],
        "recommendation": "Escape untrusted content.",
        "confidence": "high"
      }
    ]
  }
]
\`\`\``);
