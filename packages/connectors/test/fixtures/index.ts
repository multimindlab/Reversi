import type { Scenario, Subject } from "../certification.js";
import * as aws from "./aws.js";
import * as azure from "./azure.js";
import * as fs from "./fs.js";
import * as gcalendar from "./gcalendar.js";
import * as gcp from "./gcp.js";
import * as github from "./github.js";
import * as gitlab from "./gitlab.js";
import * as jira from "./jira.js";
import * as kubernetes from "./kubernetes.js";
import * as linear from "./linear.js";
import * as postgres from "./postgres.js";
import * as slack from "./slack.js";
import * as stripe from "./stripe.js";
import * as teams from "./teams.js";

export interface Fixture {
  subject: Subject;
  scenarios: Scenario[];
}

/** Every connector, in the order the docs list them. */
export const fixtures: Fixture[] = [fs, github, slack, stripe, gitlab, teams, linear, jira, gcalendar, postgres, aws, gcp, azure, kubernetes];

export { cleanup as cleanupFs } from "./fs.js";
