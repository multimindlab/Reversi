/**
 * Authentication and role-based access control.
 *
 * Principals come from API keys (with rotation: several keys may share a name, and keys can have a
 * validity window) or from OIDC bearer tokens (JWTs verified against the issuer's JWKS).
 *
 * Roles:
 *  - agent    opens runs and journals its own calls; sees only its own runs
 *  - auditor  read-only: runs, plans, ledger, evidence, metrics
 *  - approver auditor + decide approvals
 *  - operator approver + rollback, reconciliation
 *  - admin    operator + kill switch
 */
import { createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify, type JsonWebKey } from "node:crypto";

export type Role = "agent" | "auditor" | "approver" | "operator" | "admin";
export const ROLES: Role[] = ["agent", "auditor", "approver", "operator", "admin"];

export type Capability = "runs:own" | "read" | "approve" | "rollback" | "halt";

const CAPS: Record<Role, Capability[]> = {
  agent: ["runs:own"],
  auditor: ["read"],
  approver: ["read", "approve"],
  operator: ["read", "approve", "rollback"],
  admin: ["read", "approve", "rollback", "halt"],
};

export interface Principal {
  /** Recorded as the ledger `actor` for agents and compensations. */
  name: string;
  roles: Role[];
  max_permissions?: string[];
  via: "api_key" | "oidc";
}

export const can = (p: Principal, cap: Capability): boolean => p.roles.some((r) => CAPS[r].includes(cap));
export const isAgent = (p: Principal): boolean => p.roles.includes("agent") && !can(p, "read");

export interface ApiKey {
  /** Identifies the caller. For agent keys this is the `actor` recorded in the ledger. */
  name: string;
  /** One role, or several. */
  role?: Role;
  roles?: Role[];
  /** Plain key. Prefer `key_sha256` in files you keep around. */
  key?: string;
  /** Lowercase hex SHA-256 of the key. */
  key_sha256?: string;
  /** Agent keys only: the most permissions a run opened with this key may request. Omit for no cap. */
  max_permissions?: string[];
  /** ISO date or epoch ms. The key is rejected before this time. Use with `expires_at` to rotate without downtime. */
  not_before?: string | number;
  /** ISO date or epoch ms. The key is rejected from this time on. */
  expires_at?: string | number;
  disabled?: boolean;
}

const sha = (s: string) => createHash("sha256").update(s).digest();

function toMs(v: string | number | undefined, what: string, name: string): number | undefined {
  if (v === undefined) return undefined;
  const ms = typeof v === "number" ? v : Date.parse(v);
  if (!Number.isFinite(ms)) throw new Error(`key \`${name}\`: ${what} is not a valid date`);
  return ms;
}

interface Compiled {
  name: string;
  roles: Role[];
  digest: Buffer;
  max_permissions?: string[];
  not_before?: number;
  expires_at?: number;
  disabled: boolean;
}

/** Keys held in memory, replaceable at runtime (rotation without a restart). */
export class KeyRing {
  private keys: Compiled[] = [];
  constructor(
    keys: ApiKey[],
    private readonly now: () => number = Date.now,
  ) {
    this.replace(keys);
  }

  replace(keys: ApiKey[]): void {
    this.keys = keys.map((k) => {
      if (!k.key && !k.key_sha256) throw new Error(`key \`${k.name}\` needs \`key\` or \`key_sha256\``);
      const roles = k.roles ?? (k.role ? [k.role] : []);
      if (roles.length === 0 || roles.some((r) => !ROLES.includes(r))) throw new Error(`key \`${k.name}\` needs a valid role (${ROLES.join(", ")})`);
      const digest = k.key_sha256 ? Buffer.from(k.key_sha256, "hex") : sha(k.key as string);
      if (digest.length !== 32) throw new Error(`key \`${k.name}\`: key_sha256 must be 64 hex chars`);
      return {
        name: k.name,
        roles,
        digest,
        max_permissions: k.max_permissions,
        not_before: toMs(k.not_before, "not_before", k.name),
        expires_at: toMs(k.expires_at, "expires_at", k.name),
        disabled: k.disabled === true,
      };
    });
  }

  get size(): number {
    return this.keys.length;
  }

  authenticate(token: string): Principal | null {
    const d = sha(token);
    const now = this.now();
    let found: Compiled | null = null;
    // Compare every key so timing does not reveal which one matched.
    for (const k of this.keys) {
      const same = timingSafeEqual(d, k.digest);
      const live = !k.disabled && (k.not_before === undefined || now >= k.not_before) && (k.expires_at === undefined || now < k.expires_at);
      if (same && live && !found) found = k;
    }
    return found ? { name: found.name, roles: found.roles, max_permissions: found.max_permissions, via: "api_key" } : null;
  }
}

// ---- OIDC ----

export interface OidcOptions {
  issuer: string;
  /** The token's `aud` must contain this. Required: it stops tokens minted for other services working here. */
  audience: string;
  /** Defaults to the issuer's `jwks_uri` from its discovery document. */
  jwks_uri?: string;
  /** Claim holding roles; a string, a list, or a nested path like `realm_access.roles`. Default `roles`. */
  role_claim?: string;
  /** Maps claim values to Reversi roles. Unmapped values are ignored. */
  role_map: Record<string, Role>;
  /** Claim used as the principal name. Default `sub`. */
  actor_claim?: string;
  /** Caps for agent principals. */
  max_permissions?: string[];
  fetch?: typeof fetch;
  now?: () => number;
  /** Allowed clock skew in seconds. Default 60. */
  skew_seconds?: number;
}

interface Jwk extends JsonWebKey {
  kid?: string;
  use?: string;
  alg?: string;
}

const b64u = (s: string) => Buffer.from(s, "base64url");

export class OidcVerifier {
  private keys = new Map<string, Jwk>();
  private jwksUri: string | undefined;
  private lastFetch = 0;
  private readonly f: typeof fetch;
  private readonly now: () => number;
  constructor(private readonly o: OidcOptions) {
    if (!o.issuer || !o.audience) throw new Error("oidc needs `issuer` and `audience`");
    this.f = o.fetch ?? fetch;
    this.now = o.now ?? Date.now;
    this.jwksUri = o.jwks_uri;
  }

  get issuer(): string {
    return this.o.issuer;
  }

  private async refresh(): Promise<void> {
    if (this.now() - this.lastFetch < 10_000) return; // at most once per 10s, so unknown kids cannot flood the issuer
    this.lastFetch = this.now();
    if (!this.jwksUri) {
      const r = await this.f(`${this.o.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
      if (!r.ok) throw new Error(`oidc discovery failed: ${r.status}`);
      const doc = (await r.json()) as { jwks_uri?: string; issuer?: string };
      if (!doc.jwks_uri) throw new Error("oidc discovery document has no jwks_uri");
      this.jwksUri = doc.jwks_uri;
    }
    const r = await this.f(this.jwksUri);
    if (!r.ok) throw new Error(`jwks fetch failed: ${r.status}`);
    const set = (await r.json()) as { keys?: Jwk[] };
    this.keys = new Map((set.keys ?? []).filter((k) => k.kid && (k.use === undefined || k.use === "sig")).map((k) => [k.kid as string, k]));
  }

  /** Returns the principal, or null if the token is not acceptable. Never throws on a bad token. */
  async authenticate(token: string): Promise<Principal | null> {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      const header = JSON.parse(b64u(parts[0] as string).toString("utf8")) as { alg?: string; kid?: string };
      const claims = JSON.parse(b64u(parts[1] as string).toString("utf8")) as Record<string, unknown>;
      if (header.alg !== "RS256" && header.alg !== "ES256") return null; // never `none`, never HMAC
      if (!header.kid) return null;
      let jwk = this.keys.get(header.kid);
      if (!jwk) {
        await this.refresh();
        jwk = this.keys.get(header.kid);
      }
      if (!jwk) return null;
      if (jwk.alg && jwk.alg !== header.alg) return null;
      const key = createPublicKey({ key: jwk, format: "jwk" });
      const data = Buffer.from(`${parts[0]}.${parts[1]}`);
      const sig = b64u(parts[2] as string);
      const good =
        header.alg === "RS256"
          ? cryptoVerify("sha256", data, key, sig)
          : cryptoVerify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, sig);
      if (!good) return null;

      const nowS = this.now() / 1000;
      const skew = this.o.skew_seconds ?? 60;
      if (claims.iss !== this.o.issuer) return null;
      const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!aud.includes(this.o.audience)) return null;
      if (typeof claims.exp !== "number" || nowS > claims.exp + skew) return null;
      if (typeof claims.nbf === "number" && nowS < claims.nbf - skew) return null;

      const raw = (this.o.role_claim ?? "roles").split(".").reduce<unknown>((o, k) => (typeof o === "object" && o !== null ? (o as Record<string, unknown>)[k] : undefined), claims);
      const values = typeof raw === "string" ? raw.split(/[\s,]+/) : Array.isArray(raw) ? raw.filter((x): x is string => typeof x === "string") : [];
      const roles = [...new Set(values.map((v) => this.o.role_map[v]).filter((r): r is Role => !!r))];
      if (roles.length === 0) return null;
      const name = claims[this.o.actor_claim ?? "sub"];
      if (typeof name !== "string" || !name) return null;
      return { name, roles, max_permissions: this.o.max_permissions, via: "oidc" };
    } catch {
      return null;
    }
  }
}
