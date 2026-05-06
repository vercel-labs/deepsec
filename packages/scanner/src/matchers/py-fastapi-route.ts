import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

export const pyFastapiRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "py-fastapi-route",
  description: "FastAPI route handlers — entry points (gated on FastAPI)",
  filePatterns: ["**/*.py"],
  requires: { tech: ["fastapi"] },
  examples: [
    `@app.get("/users")`,
    `@router.post("/items", response_model=Item)`,
    `@api.put("/things/{id}")`,
    `@app.delete("/users/{user_id}")`,
    `   @router.patch("/x")`,
    `@app.websocket("/ws")`,
    `router = APIRouter(prefix="/v1")`,
    `def read_user(user_id: int, current = Depends(get_current_user)):`,
    `def admin(current_user = Security(get_current_active_user, scopes=["admin"])):`,
  ],
  match(content, filePath) {
    if (/\b(?:tests?|migrations)\b/i.test(filePath)) return [];

    return regexMatcher(
      "py-fastapi-route",
      [
        {
          regex:
            /^\s*@(?:app|router|api)\.(?:get|post|put|patch|delete|options|head|websocket)\s*\(/m,
          label: "FastAPI route decorator",
        },
        { regex: /\bAPIRouter\s*\(/, label: "APIRouter() factory" },
        {
          regex: /=\s*Depends\s*\(/,
          label: "Depends(...) dependency (auth gate when wired up)",
        },
        { regex: /\bSecurity\s*\(/, label: "Security(...) — auth dependency" },
      ],
      content,
    );
  },
};
