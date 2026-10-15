/**
 * Sealed permission scopes.
 *
 * A scope is the set of permissions a run may use. `SealedScope.seal` hashes the set (SHA-256) when
 * the run starts. Code can check permissions and verify the seal, but cannot add to the set without
 * producing a different seal. Narrowing (attenuation) is allowed and records the parent's seal, so
 * delegation chains are auditable.
 */
import { createHash } from "node:crypto";

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopeError";
  }
}

function sealOf(permissions: readonly string[], parent: string | null): string {
  const h = createHash("sha256");
  if (parent) h.update(parent, "utf8");
  for (const p of permissions) {
    const bytes = Buffer.from(p, "utf8");
    const len = Buffer.alloc(8);
    len.writeBigUInt64LE(BigInt(bytes.length));
    h.update(len); // length-prefixed, so ["ab","c"] and ["a","bc"] seal differently
    h.update(bytes);
  }
  return h.digest("hex");
}

function normalise(perms: Iterable<string>): string[] {
  return [...new Set(perms)].sort();
}

export class SealedScope {
  private constructor(
    private readonly perms: readonly string[],
    readonly seal: string,
    readonly parentSeal: string | null,
  ) {
    Object.freeze(this.perms);
  }

  static seal(permissions: Iterable<string>): SealedScope {
    const perms = normalise(permissions);
    return new SealedScope(perms, sealOf(perms, null), null);
  }

  /** Rebuild a scope from stored data. Throws if the stored seal does not match its contents. */
  static restore(permissions: Iterable<string>, seal: string, parentSeal: string | null): SealedScope {
    const perms = normalise(permissions);
    if (sealOf(perms, parentSeal) !== seal) {
      throw new ScopeError("scope seal does not match its contents");
    }
    return new SealedScope(perms, seal, parentSeal);
  }

  permissions(): string[] {
    return [...this.perms];
  }

  has(permission: string): boolean {
    return this.perms.includes(permission);
  }

  /** Re-hash the contents and compare with the stored seal. */
  verify(): boolean {
    return sealOf(this.perms, this.parentSeal) === this.seal;
  }

  /** Derive a narrower scope for one task. Throws if it asks for anything the parent lacks. */
  attenuate(subset: Iterable<string>): SealedScope {
    const perms = normalise(subset);
    for (const p of perms) {
      if (!this.has(p)) throw new ScopeError(`cannot attenuate: \`${p}\` is not held by the parent scope`);
    }
    return new SealedScope(perms, sealOf(perms, this.seal), this.seal);
  }
}
