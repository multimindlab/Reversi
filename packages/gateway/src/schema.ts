/** A small JSON Schema checker for MCP tool arguments and results: type, enum, const, required, properties, additionalProperties, items, bounds, pattern, composition. */
type Schema = Record<string, unknown>;

const typeOf = (v: unknown): string => (v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v);
const isRec = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export function validateSchema(schema: unknown, value: unknown, path = "$", depth = 0): string[] {
  if (!isRec(schema) || depth > 12) return [];
  const s = schema as Schema;
  const out: string[] = [];
  const t = typeOf(value);

  if (s.type !== undefined) {
    const allowed = (Array.isArray(s.type) ? s.type : [s.type]) as string[];
    const okType = allowed.some((x) => x === t || (x === "number" && t === "integer"));
    if (!okType) return [`${path}: expected ${allowed.join(" or ")}, got ${t}`];
  }
  if (Array.isArray(s.enum) && !s.enum.some((e) => same(e, value))) out.push(`${path}: must be one of ${JSON.stringify(s.enum).slice(0, 80)}`);
  if ("const" in s && !same(s.const, value)) out.push(`${path}: must equal ${JSON.stringify(s.const).slice(0, 60)}`);

  if (typeof value === "number") {
    if (typeof s.minimum === "number" && value < s.minimum) out.push(`${path}: below minimum ${s.minimum}`);
    if (typeof s.maximum === "number" && value > s.maximum) out.push(`${path}: above maximum ${s.maximum}`);
    if (typeof s.exclusiveMinimum === "number" && value <= s.exclusiveMinimum) out.push(`${path}: must be above ${s.exclusiveMinimum}`);
    if (typeof s.exclusiveMaximum === "number" && value >= s.exclusiveMaximum) out.push(`${path}: must be below ${s.exclusiveMaximum}`);
    if (typeof s.multipleOf === "number" && s.multipleOf > 0 && Math.abs(value / s.multipleOf - Math.round(value / s.multipleOf)) > 1e-9) out.push(`${path}: must be a multiple of ${s.multipleOf}`);
  }
  if (typeof value === "string") {
    if (typeof s.minLength === "number" && value.length < s.minLength) out.push(`${path}: shorter than ${s.minLength}`);
    if (typeof s.maxLength === "number" && value.length > s.maxLength) out.push(`${path}: longer than ${s.maxLength}`);
    if (typeof s.pattern === "string") {
      try {
        if (!new RegExp(s.pattern, "u").test(value)) out.push(`${path}: does not match ${s.pattern}`);
      } catch {
        /* an unreadable pattern in the upstream's schema is not the caller's fault */
      }
    }
  }
  if (Array.isArray(value)) {
    if (typeof s.minItems === "number" && value.length < s.minItems) out.push(`${path}: fewer than ${s.minItems} items`);
    if (typeof s.maxItems === "number" && value.length > s.maxItems) out.push(`${path}: more than ${s.maxItems} items`);
    if (isRec(s.items)) value.slice(0, 200).forEach((v, i) => out.push(...validateSchema(s.items, v, `${path}[${i}]`, depth + 1)));
  }
  if (isRec(value)) {
    const props = isRec(s.properties) ? s.properties : {};
    for (const r of Array.isArray(s.required) ? (s.required as string[]) : []) if (!(r in value)) out.push(`${path}: missing required \`${r}\``);
    for (const [k, v] of Object.entries(value)) {
      if (k in props) out.push(...validateSchema(props[k], v, `${path}.${k}`, depth + 1));
      else if (s.additionalProperties === false) out.push(`${path}: unexpected \`${k}\``);
      else if (isRec(s.additionalProperties)) out.push(...validateSchema(s.additionalProperties, v, `${path}.${k}`, depth + 1));
    }
  }
  if (Array.isArray(s.allOf)) for (const sub of s.allOf) out.push(...validateSchema(sub, value, path, depth + 1));
  if (Array.isArray(s.anyOf) && s.anyOf.length && !s.anyOf.some((sub) => validateSchema(sub, value, path, depth + 1).length === 0)) out.push(`${path}: matches none of the allowed shapes`);
  if (Array.isArray(s.oneOf) && s.oneOf.length && s.oneOf.filter((sub) => validateSchema(sub, value, path, depth + 1).length === 0).length !== 1) out.push(`${path}: must match exactly one allowed shape`);
  return out.slice(0, 10);
}
