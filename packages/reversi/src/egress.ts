/**
 * Control over where Reversi itself sends data: webhooks, anchors, notifications, trace export and the upstream servers
 * the gateway connects to. An allowlist of hosts (also the data-residency control: only destinations in your region),
 * and protection against being pointed at internal addresses (SSRF), with the cloud metadata endpoints always refused.
 */
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { globMatch } from "./glob.js";

export interface EgressConfig {
  /** Host globs destinations must match (`*.eu.example.com`). Unset: any host. */
  allow?: string[];
  /** Refuse loopback, private and link-local addresses. Off by default so local development works. */
  block_private?: boolean;
  /** Allow cloud metadata addresses (169.254.169.254 and friends). Never needed; off. */
  allow_metadata?: boolean;
  /** Where this deployment's data lives, recorded in bundles and reports. */
  region?: string;
}

export class EgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EgressError";
  }
}

function ipv4(ip: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  return m ? m.slice(1).map(Number) : null;
}

export function isMetadataAddress(ip: string): boolean {
  const v = ip.toLowerCase().replace(/^::ffff:/, "");
  return v === "169.254.169.254" || v === "100.100.100.200" || v === "fd00:ec2::254" || v === "192.0.0.192";
}

export function isPrivateAddress(ipIn: string): boolean {
  const ip = ipIn.toLowerCase().replace(/^::ffff:/, "");
  const v4 = ipv4(ip);
  if (v4) {
    const [a, b] = v4 as [number, number, number, number];
    return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  return ip === "::1" || ip === "::" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe8") || ip.startsWith("fe9") || ip.startsWith("fea") || ip.startsWith("feb");
}

/** Throws EgressError unless the URL may be contacted. Resolves the host, so a name that points inside is caught too. */
export async function checkUrl(cfg: EgressConfig | undefined, raw: string | URL): Promise<URL> {
  const url = typeof raw === "string" ? new URL(raw) : raw;
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new EgressError(`only http(s) destinations are allowed, not ${url.protocol}`);
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (cfg?.allow?.length && !cfg.allow.some((g) => globMatch(g.toLowerCase(), host) || globMatch(g.toLowerCase(), url.host.toLowerCase()))) {
    throw new EgressError(`${host} is not in the egress allowlist${cfg.region ? ` (region ${cfg.region})` : ""}`);
  }
  const addrs = isIP(host) ? [host] : (await lookup(host, { all: true }).catch(() => [])).map((a) => a.address);
  for (const a of addrs) {
    if (!cfg?.allow_metadata && isMetadataAddress(a)) throw new EgressError(`${host} resolves to a cloud metadata address (${a}), which is never allowed`);
    if (cfg?.block_private && isPrivateAddress(a)) throw new EgressError(`${host} resolves to a private or loopback address (${a}) and egress.block_private is on`);
  }
  return url;
}

/** `fetch` that checks every destination first, and every redirect (up to 3) the same way. */
export function guardedFetch(cfg: EgressConfig | undefined, f: typeof fetch = fetch): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    let url = await checkUrl(cfg, typeof input === "string" || input instanceof URL ? input : input.url);
    for (let hop = 0; ; hop++) {
      const res = await f(url, { ...init, redirect: "manual" });
      if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
        if (hop >= 3) throw new EgressError("too many redirects");
        url = await checkUrl(cfg, new URL(res.headers.get("location") as string, url));
        continue;
      }
      return res;
    }
  }) as typeof fetch;
}

export function egressFromEnv(env: Record<string, string | undefined> = process.env): EgressConfig {
  return {
    allow: env.REVERSI_EGRESS_ALLOW ? env.REVERSI_EGRESS_ALLOW.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
    block_private: env.REVERSI_EGRESS_BLOCK_PRIVATE === "1",
    region: env.REVERSI_REGION,
  };
}
