import type { AgentPlugin } from "./types.js";

export class AgentRegistry {
  private agents = new Map<string, AgentPlugin>();

  register(plugin: AgentPlugin, opts: { allowOverride?: boolean } = {}): void {
    if (this.agents.has(plugin.type) && !opts.allowOverride && !plugin.allowOverride) {
      throw new Error(
        `Agent type ${JSON.stringify(plugin.type)} is already registered. ` +
          `Use a namespaced type or set allowOverride: true explicitly.`,
      );
    }
    this.agents.set(plugin.type, plugin);
  }

  get(type: string): AgentPlugin | undefined {
    return this.agents.get(type);
  }

  types(): string[] {
    return Array.from(this.agents.keys());
  }
}
