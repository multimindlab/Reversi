#!/usr/bin/env node
// A throwaway OpenID provider for trying Reversi's OIDC support by hand. NOT for production.
//   node examples/oidc/mock-idp.mjs            # listens on http://127.0.0.1:9000
//   curl -s "http://127.0.0.1:9000/token?sub=alice&roles=reversi-ops"      # prints a signed access token
// Point Reversi at it:
//   REVERSI_OIDC_ISSUER=http://127.0.0.1:9000 REVERSI_OIDC_AUDIENCE=reversi \
//   REVERSI_OIDC_ROLE_MAP='{"reversi-ops":"operator","reversi-agents":"agent"}' ...
import { createServer } from "node:http";
import { createSign, generateKeyPairSync } from "node:crypto";

const PORT = Number(process.env.PORT ?? 9000);
const ISSUER = `http://127.0.0.1:${PORT}`;
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "mock-1", use: "sig", alg: "RS256" };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

function token({ sub, roles, aud, ttl }) {
  const now = Math.floor(Date.now() / 1000);
  const data = `${b64({ alg: "RS256", kid: "mock-1", typ: "JWT" })}.${b64({ iss: ISSUER, aud, sub, roles, iat: now, exp: now + ttl })}`;
  return `${data}.${createSign("sha256").update(data).sign(privateKey).toString("base64url")}`;
}

createServer((req, res) => {
  const u = new URL(req.url, ISSUER);
  const send = (status, body) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  if (u.pathname === "/.well-known/openid-configuration") return send(200, { issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` });
  if (u.pathname === "/jwks") return send(200, { keys: [jwk] });
  if (u.pathname === "/token") {
    const q = u.searchParams;
    const t = token({ sub: q.get("sub") ?? "alice", roles: (q.get("roles") ?? "").split(",").filter(Boolean), aud: q.get("aud") ?? "reversi", ttl: Number(q.get("ttl") ?? 3600) });
    res.writeHead(200, { "content-type": "text/plain" });
    return res.end(t);
  }
  send(404, { error: "not found" });
}).listen(PORT, "127.0.0.1", () => console.error(`mock IdP on ${ISSUER}  (try: curl -s "${ISSUER}/token?sub=alice&roles=reversi-ops")`));
