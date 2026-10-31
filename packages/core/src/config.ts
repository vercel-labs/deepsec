import type {
  AgentPluginRef,
  DeepsecPlugin,
  ExecutorProvider,
  MatcherPlugin,
  NotifierPlugin,
  OwnershipProvider,
  PeopleProvider,
} from "./plugin.js";

/** A project the user wants to scan. */
export interface ProjectDeclaration {
  id: string;
  /** Absolute or relative path to the codebase root. */
  root: string;
  /** Optional GitHub URL of the form `https://github.com/owner/repo/blob/branch`. */
  githubUrl?: string;
  /** Markdown injected into the AI prompt as repo context (replaces `data/<id>/INFO.md`). */
  infoMarkdown?: string;
  /** Free-form text appended to the AI prompt for this project. */
  promptAppend?: string;
  /** Path prefixes that should be processed before others. */
  priorityPaths?: string[];
}

export interface DeepsecConfig {
  projects: ProjectDeclaration[];
  plugins?: DeepsecPlugin[];
  /** Filter the matcher set used by `scan`. */
  matchers?: { only?: string[]; exclude?: string[] };
  defaultAgent?: string;
  /** Default model selected during setup; CLI --model overrides it. */
  defaultModel?: string;
  /** Harness-neutral effort level selected with the default model. */
  defaultThinkingLevel?: string;
  /** Non-secret default model credential route. Secret values stay in env/.env.local. */
  ai?: {
    mode: "gateway" | "direct" | "custom" | "local";
    provider: string;
    apiKeyEnv?: string;
    baseUrl?: string;
    /** Custom providers may declare the secret-bearing request header without storing its value. */
    credentialHeader?: { name: string; scheme: "bearer" | "raw" };
  };
  /** Override the data directory (default: `./data`). */
  dataDir?: string;
}

/** Identity helper that gives users autocomplete on the config object. */
export function defineConfig(config: DeepsecConfig): DeepsecConfig {
  return config;
}

/**
 * Merged view of every plugin's contributions. Built once at CLI startup.
 *
 * Resolution rules:
 * - matchers / agents / notifiers: additive across plugins.
 * - ownership / people / executor: last plugin to declare the slot wins.
 *   This lets a more specific plugin override a default.
 */
export class PluginRegistry {
  matchers: MatcherPlugin[] = [];
  agents: AgentPluginRef[] = [];
  notifiers: NotifierPlugin[] = [];
  ownership?: OwnershipProvider;
  people?: PeopleProvider;
  executor?: ExecutorProvider;
  commands: Array<(program: unknown) => void> = [];

  add(plugin: DeepsecPlugin): void {
    if (plugin.matchers) this.matchers.push(...plugin.matchers);
    if (plugin.agents) this.agents.push(...plugin.agents);
    if (plugin.notifiers) this.notifiers.push(...plugin.notifiers);
    if (plugin.ownership) this.ownership = plugin.ownership;
    if (plugin.people) this.people = plugin.people;
    if (plugin.executor) this.executor = plugin.executor;
    if (plugin.commands) this.commands.push(plugin.commands);
  }
}

// --- Singleton accessor used by commands at runtime ---

let _registry: PluginRegistry = new PluginRegistry();
let _config: DeepsecConfig | undefined;
let _configPath: string | undefined;

export function getRegistry(): PluginRegistry {
  return _registry;
}

export function getConfig(): DeepsecConfig | undefined {
  return _config;
}

/** Absolute path to the loaded config file, or `undefined` if no config loaded. */
export function getConfigPath(): string | undefined {
  return _configPath;
}

/** Wired up by the CLI bootstrap after a config file has been loaded. */
export function setLoadedConfig(config: DeepsecConfig, configPath?: string): void {
  _config = config;
  _configPath = configPath;
  _registry = new PluginRegistry();
  for (const plugin of config.plugins ?? []) {
    _registry.add(plugin);
  }
}

/** Lookup a project by id, falling back to undefined. */
export function findProject(id: string): ProjectDeclaration | undefined {
  return _config?.projects.find((p) => p.id === id);
}
