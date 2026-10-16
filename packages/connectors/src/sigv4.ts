import { createHash, createHmac } from "node:crypto";

/** AWS Signature Version 4 request signing (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4-create-signed-request.html). */

export interface SigV4Input {
  method: string;
  /** Already URI-encoded path, starting with `/`. For S3 it is encoded once. */
  canonicalUri: string;
  /** Raw (not yet encoded) query parameters. */
  query?: Array<[string, string]>;
  /** Every header to sign, including `host` and `x-amz-date`. Names are case-insensitive. */
  headers: Record<string, string>;
  /** Lowercase hex SHA-256 of the body. */
  payloadHash: string;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  /** `YYYYMMDDTHHMMSSZ` */
  amzDate: string;
}

export interface SigV4Output {
  authorization: string;
  signedHeaders: string;
  canonicalRequest: string;
  stringToSign: string;
  signature: string;
  /** The headers that were signed, lowercased (including `x-amz-security-token` when a session token is used). */
  headers: Record<string, string>;
}

export const sha256Hex = (data: string | Uint8Array): string => createHash("sha256").update(data).digest("hex");

const hmac = (key: string | Buffer, data: string): Buffer => createHmac("sha256", key).update(data, "utf8").digest();

/** RFC 3986 percent-encoding as AWS defines it: only A-Z a-z 0-9 - _ . ~ stay; `/` stays when `keepSlash`. */
export function uriEncode(s: string, keepSlash = false): string {
  let out = "";
  for (const ch of s) {
    if (/^[A-Za-z0-9\-_.~]$/.test(ch) || (keepSlash && ch === "/")) out += ch;
    else out += [...Buffer.from(ch, "utf8")].map((b) => "%" + b.toString(16).toUpperCase().padStart(2, "0")).join("");
  }
  return out;
}

/** Query parameters encoded and sorted the way SigV4 requires; use the same string in the request URL. */
export function canonicalQueryString(query: Array<[string, string]>): string {
  return query
    .map(([k, v]) => [uriEncode(k), uriEncode(v)] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
}

export function signingKey(secretAccessKey: string, dateStamp: string, region: string, service: string): Buffer {
  const kDate = hmac("AWS4" + secretAccessKey, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

export function signV4(i: SigV4Input): SigV4Output {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(i.headers)) headers[k.toLowerCase()] = v.trim().replace(/\s+/g, " ");
  if (i.sessionToken) headers["x-amz-security-token"] = i.sessionToken;
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((n) => `${n}:${headers[n]}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalQuery = canonicalQueryString(i.query ?? []);
  const canonicalRequest = [i.method.toUpperCase(), i.canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, i.payloadHash].join(
    "\n",
  );
  const dateStamp = i.amzDate.slice(0, 8);
  const scope = `${dateStamp}/${i.region}/${i.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", i.amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const signature = createHmac("sha256", signingKey(i.secretAccessKey, dateStamp, i.region, i.service))
    .update(stringToSign, "utf8")
    .digest("hex");
  const authorization = `AWS4-HMAC-SHA256 Credential=${i.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { authorization, signedHeaders, canonicalRequest, stringToSign, signature, headers };
}

export function amzDateOf(d: Date): string {
  return d.toISOString().replace(/[:-]|\.\d{3}/g, "");
}
