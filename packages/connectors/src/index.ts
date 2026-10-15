import type { Connector } from "./common.js";
import { createFilesystemConnector, type FilesystemConfig } from "./filesystem.js";
import { createGithubConnector, type GithubConfig } from "./github.js";
import { createSlackConnector, type SlackConfig } from "./slack.js";
import { createStripeConnector, type StripeConfig } from "./stripe.js";

export {
  HttpError,
  type Connector,
  type Fetch,
  type ToolContext,
  type ToolHandler,
} from "./common.js";
export { compensatorFor } from "./compensate.js";
export { createFilesystemConnector, type FilesystemConfig } from "./filesystem.js";
export { createGithubConnector, type GithubConfig } from "./github.js";
export { createConnectorServer } from "./server.js";
export { createSlackConnector, type SlackConfig } from "./slack.js";
export { createStripeConnector, type StripeConfig } from "./stripe.js";

export interface AllConnectorsConfig {
  fs?: FilesystemConfig;
  github?: GithubConfig;
  slack?: SlackConfig;
  stripe?: StripeConfig;
}

/** Build every connector that has a config entry. */
export function allConnectors(config: AllConnectorsConfig): Connector[] {
  const out: Connector[] = [];
  if (config.fs) out.push(createFilesystemConnector(config.fs));
  if (config.github) out.push(createGithubConnector(config.github));
  if (config.slack) out.push(createSlackConnector(config.slack));
  if (config.stripe) out.push(createStripeConnector(config.stripe));
  return out;
}
