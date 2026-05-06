import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyCeleryTaskMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-celery-task",
  description: "Celery task definitions — background-job auth-gap surface (gated on Celery)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["celery"] },
  examples: [
    `@app.task`,
    `@celery.task(bind=True, max_retries=3)`,
    `@shared_task.task`,
    `@shared_task`,
    `   @shared_task(name="tasks.send_email")`,
    `send_email.delay(user_id, subject)`,
    `process_job.apply_async(args=[1, 2], countdown=10)`,
    `app = Celery("worker", broker="redis://localhost")`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-celery-task",
      [
        { regex: /^\s*@(?:app|celery|shared_task)\.task\b/m, label: "@app.task / @celery.task" },
        { regex: /^\s*@shared_task\b/m, label: "@shared_task decorator" },
        {
          regex: /\.delay\s*\(|\.apply_async\s*\(/,
          label: "task.delay/apply_async dispatch site",
        },
        { regex: /\bCelery\s*\(\s*['"]/, label: "Celery('app') init" },
      ],
      content,
    );
  },
};
