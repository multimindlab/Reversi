import { describe, expect, it } from "vitest";
import { canonicalize, hashPayload, sha256Hex } from "../src/index.js";

describe("canonicalize", () => {
  it("sorts keys at every level and strips whitespace", () => {
    expect(canonicalize({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: "x" } })).toBe(
      '{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}',
    );
  });

  it("omits undefined object values and nulls undefined array items", () => {
    expect(canonicalize({ a: undefined, b: 1 })).toBe('{"b":1}');
    expect(canonicalize([1, undefined])).toBe("[1,null]");
  });

  it("is independent of insertion order", () => {
    expect(canonicalize({ x: 1, y: 2 })).toBe(canonicalize({ y: 2, x: 1 }));
  });

  it("rejects values with no canonical form", () => {
    expect(() => canonicalize(NaN)).toThrow(TypeError);
    expect(() => canonicalize(Infinity)).toThrow(TypeError);
    expect(() => canonicalize(new Map())).toThrow(TypeError);
    expect(() => canonicalize(10n)).toThrow(TypeError);
    expect(() => canonicalize(() => 1)).toThrow(TypeError);
  });

  it("matches the SHA-256 test vector for 'abc'", () => {
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

describe("hashPayload", () => {
  it("never throws, even for values without a canonical form", () => {
    expect(() => hashPayload(NaN)).not.toThrow();
    expect(hashPayload(NaN)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("treats undefined as null", () => {
    expect(hashPayload(undefined)).toBe(hashPayload(null));
  });

  it("is stable for equal payloads and differs for different ones", () => {
    expect(hashPayload({ a: 1, b: 2 })).toBe(hashPayload({ b: 2, a: 1 }));
    expect(hashPayload({ a: 1 })).not.toBe(hashPayload({ a: 2 }));
  });
});
