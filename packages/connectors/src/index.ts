import type { Connector } from "./common.js";
import { createAwsConnector, type AwsConfig } from "./aws.js";
import { createAzureConnector, type AzureConfig } from "./azure.js";
import { createFilesystemConnector, type FilesystemConfig } from "./filesystem.js";
import { createGcalendarConnector, type GcalendarConfig } from "./gcalendar.js";
import { createGcpConnector, type GcpConfig } from "./gcp.js";
import { createGithubConnector, type GithubConfig } from "./github.js";
import { createGitlabConnector, type GitlabConfig } from "./gitlab.js";
import { createJiraConnector, type JiraConfig } from "./jira.js";
import { createKubernetesConnector, type KubernetesConfig } from "./kubernetes.js";
import { createLinearConnector, type LinearConfig } from "./linear.js";
import { createPostgresConnector, type PostgresConfig } from "./postgres.js";
import { createSlackConnector, type SlackConfig } from "./slack.js";
import { createStripeConnector, type StripeConfig } from "./stripe.js";
import { createTeamsConnector, type TeamsConfig } from "./teams.js";

export {
  HttpError,
  type Connector,
  type Fetch,
  type ToolContext,
  type ToolHandler,
} from "./common.js";
export { compensatorFor } from "./compensate.js";
export { createAwsConnector, type AwsConfig } from "./aws.js";
export { createAzureConnector, type AzureConfig } from "./azure.js";
export { createFilesystemConnector, type FilesystemConfig } from "./filesystem.js";
export { createGcalendarConnector, type GcalendarConfig } from "./gcalendar.js";
export { createGcpConnector, type GcpConfig } from "./gcp.js";
export { createGithubConnector, type GithubConfig } from "./github.js";
export { createGitlabConnector, type GitlabConfig } from "./gitlab.js";
export { createJiraConnector, type JiraConfig } from "./jira.js";
export { caFetch, createKubernetesConnector, type KubernetesConfig } from "./kubernetes.js";
export { createLinearConnector, type LinearConfig } from "./linear.js";
export {
  createPgPool,
  createPostgresConnector,
  type PgClientLike,
  type PgLike,
  type PgResult,
  type PostgresConfig,
} from "./postgres.js";
export { createConnectorServer } from "./server.js";
export { createSlackConnector, type SlackConfig } from "./slack.js";
export { createStripeConnector, type StripeConfig } from "./stripe.js";
export { createTeamsConnector, type TeamsConfig } from "./teams.js";
export { amzDateOf, signV4, signingKey, uriEncode, type SigV4Input, type SigV4Output } from "./sigv4.js";
export {
  CHECKS,
  CHECK_IDS,
  certificationFailures,
  connectorSchemaHashes,
  detectManifestDrift,
  renderCertificationMatrix,
  type Certification,
  type CheckId,
  type CheckResult,
  type CheckStatus,
  type ManifestDrift,
} from "./certify.js";

export interface AllConnectorsConfig {
  fs?: FilesystemConfig;
  github?: GithubConfig;
  slack?: SlackConfig;
  stripe?: StripeConfig;
  gitlab?: GitlabConfig;
  teams?: TeamsConfig;
  linear?: LinearConfig;
  jira?: JiraConfig;
  gcalendar?: GcalendarConfig;
  postgres?: PostgresConfig;
  aws?: AwsConfig;
  gcp?: GcpConfig;
  azure?: AzureConfig;
  kubernetes?: KubernetesConfig;
}

/** Build every connector that has a config entry. */
export function allConnectors(config: AllConnectorsConfig): Connector[] {
  const out: Connector[] = [];
  if (config.fs) out.push(createFilesystemConnector(config.fs));
  if (config.github) out.push(createGithubConnector(config.github));
  if (config.slack) out.push(createSlackConnector(config.slack));
  if (config.stripe) out.push(createStripeConnector(config.stripe));
  if (config.gitlab) out.push(createGitlabConnector(config.gitlab));
  if (config.teams) out.push(createTeamsConnector(config.teams));
  if (config.linear) out.push(createLinearConnector(config.linear));
  if (config.jira) out.push(createJiraConnector(config.jira));
  if (config.gcalendar) out.push(createGcalendarConnector(config.gcalendar));
  if (config.postgres) out.push(createPostgresConnector(config.postgres));
  if (config.aws) out.push(createAwsConnector(config.aws));
  if (config.gcp) out.push(createGcpConnector(config.gcp));
  if (config.azure) out.push(createAzureConnector(config.azure));
  if (config.kubernetes) out.push(createKubernetesConnector(config.kubernetes));
  return out;
}
