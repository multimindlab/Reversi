import { createHash } from "node:crypto";

/**
 * Deterministic JSON: object keys sorted, no whitespace, `undefined` object values omitted.
 * Compatible with RFC 8785 (JCS) for strings, integers, booleans, null, arrays and plain objects.
 * Throws on values that have no canonical form (NaN, Infinity, bigint, functions, Map, Set, ...).
 */
export function canonicalize(value: unknown): string {
  return canon(value, "$");
}

function canon(value: unknown, path: string): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError(`cannot canonicalize a non-finite number at ${path}`);
      }
      return JSON.stringify(value);
    case "object": {
      const withToJson = value as { toJSON?: () => unknown };
      if (typeof withToJson.toJSON === "function") return canon(withToJson.toJSON(), path);
      if (Array.isArray(value)) {
        return (
          "[" +
          value.map((x, i) => (x === undefined ? "null" : canon(x, `${path}[${i}]`))).join(",") +
          "]"
        );
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError(`cannot canonicalize a non-plain object at ${path}`);
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return (
        "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(obj[k], `${path}.${k}`)).join(",") + "}"
      );
    }
    default:
      throw new TypeError(`cannot canonicalize a value of type ${typeof value} at ${path}`);
  }
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Hash of an arbitrary payload (call arguments, a result, a compensation handle).
 * Values without a canonical form hash as a fixed marker rather than throwing, so a
 * strange tool result can never stop an action from being journaled.
 */
export function hashPayload(value: unknown): string {
  try {
    return sha256Hex(canonicalize(value === undefined ? null : value));
  } catch {
    return sha256Hex("unhashable");
  }
}
