import { describe, expect, it } from "vitest";
import { amzDateOf, signV4, signingKey, uriEncode } from "../src/index.js";
import { sha256Hex } from "../src/sigv4.js";

// The documented credentials used throughout the AWS Signature Version 4 test suite and examples.
const ACCESS_KEY_ID = "AKIDEXAMPLE";
const SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

describe("SigV4 against the AWS documented test vectors", () => {
  it("get-vanilla from the SigV4 test suite", () => {
    const out = signV4({
      method: "GET",
      canonicalUri: "/",
      headers: { Host: "example.amazonaws.com", "X-Amz-Date": "20150830T123600Z" },
      payloadHash: sha256Hex(""),
      region: "us-east-1",
      service: "service",
      accessKeyId: ACCESS_KEY_ID,
      secretAccessKey: SECRET,
      amzDate: "20150830T123600Z",
    });
    // get-vanilla.creq
    expect(out.canonicalRequest).toBe(
      [
        "GET",
        "/",
        "",
        "host:example.amazonaws.com",
        "x-amz-date:20150830T123600Z",
        "",
        "host;x-amz-date",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      ].join("\n"),
    );
    // get-vanilla.sts
    expect(out.stringToSign).toBe(
      [
        "AWS4-HMAC-SHA256",
        "20150830T123600Z",
        "20150830/us-east-1/service/aws4_request",
        "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
      ].join("\n"),
    );
    // get-vanilla.authz
    expect(out.signature).toBe("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    expect(out.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    );
  });

  it("derives the documented signing key (IAM example, 20150830/us-east-1/iam)", () => {
    expect(signingKey(SECRET, "20150830", "us-east-1", "iam").toString("hex")).toBe(
      "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
    );
  });

  it("sorts and encodes query parameters, and orders signed headers", () => {
    const out = signV4({
      method: "GET",
      canonicalUri: "/",
      query: [["b", "2"], ["a", "x y"], ["a", "1"]],
      headers: { "X-Amz-Date": "20150830T123600Z", Host: "example.amazonaws.com" },
      payloadHash: sha256Hex(""),
      region: "us-east-1",
      service: "service",
      accessKeyId: ACCESS_KEY_ID,
      secretAccessKey: SECRET,
      amzDate: "20150830T123600Z",
    });
    expect(out.canonicalRequest.split("\n")[2]).toBe("a=1&a=x%20y&b=2");
    expect(out.signedHeaders).toBe("host;x-amz-date");
  });

  it("signs the session token header when one is given", () => {
    const out = signV4({
      method: "GET",
      canonicalUri: "/",
      headers: { host: "example.amazonaws.com", "x-amz-date": "20150830T123600Z" },
      payloadHash: sha256Hex(""),
      region: "us-east-1",
      service: "service",
      accessKeyId: ACCESS_KEY_ID,
      secretAccessKey: SECRET,
      sessionToken: "TOKEN",
      amzDate: "20150830T123600Z",
    });
    expect(out.signedHeaders).toBe("host;x-amz-date;x-amz-security-token");
    expect(out.headers["x-amz-security-token"]).toBe("TOKEN");
    expect(out.signature).not.toBe("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
  });

  it("encodes URIs the way AWS requires", () => {
    expect(uriEncode("a b/c~d-e_f.g")).toBe("a%20b%2Fc~d-e_f.g");
    expect(uriEncode("a b/c", true)).toBe("a%20b/c");
    expect(uriEncode("é*!'()")).toBe("%C3%A9%2A%21%27%28%29");
    expect(amzDateOf(new Date("2015-08-30T12:36:00.123Z"))).toBe("20150830T123600Z");
  });
});
