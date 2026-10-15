const cache = new Map<string, RegExp>();

/** `*` matches any run of characters, `?` one character. Everything else is literal. */
export function globMatch(pattern: string, value: string): boolean {
  let re = cache.get(pattern);
  if (!re) {
    re = new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "s");
    cache.set(pattern, re);
  }
  return re.test(value);
}

export function globAny(patterns: string | string[] | undefined, value: string): boolean {
  if (patterns === undefined) return true;
  return (Array.isArray(patterns) ? patterns : [patterns]).some((p) => globMatch(p, value));
}
