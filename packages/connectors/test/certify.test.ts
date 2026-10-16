import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { CHECK_IDS, certificationFailures, renderCertificationMatrix, type Certification } from "../src/index.js";
import { certifyConnector } from "./certification.js";
import { cleanupFs, fixtures } from "./fixtures/index.js";

afterAll(cleanupFs);

// Certification runs once per connector; the tests below assert on the recorded results.
const certifications: Certification[] = [];
for (const f of fixtures) certifications.push(await certifyConnector(f.subject, f.scenarios));

describe("connector certification", () => {
  it("covers all fourteen connectors", () => {
    expect(certifications.map((c) => c.connector)).toEqual([
      "fs", "github", "slack", "stripe", "gitlab", "teams", "linear", "jira", "gcalendar", "postgres", "aws", "gcp", "azure", "kubernetes",
    ]);
  });

  describe.each(certifications)("$connector", (cert) => {
    it("records a result for each of the twelve checks", () => {
      expect(cert.results.map((r) => r.check)).toEqual([...CHECK_IDS]);
    });

    it.each(CHECK_IDS)("%s", (id) => {
      const r = cert.results.find((x) => x.check === id)!;
      expect(r.status, `${cert.connector}: ${id}: ${r.reason ?? ""}`).not.toBe("fail");
      if (r.status === "not_applicable") expect(r.reason, "not_applicable needs a reason").toBeTruthy();
    });

    it("has no failing check", () => {
      expect(certificationFailures(cert)).toEqual([]);
    });
  });

  it("documents the matrix and every not-applicable reason in docs/connectors.mdx", () => {
    const docs = readFileSync(fileURLToPath(new URL("../../../docs/connectors.mdx", import.meta.url)), "utf8");
    for (const line of renderCertificationMatrix(certifications).split("\n")) expect(docs).toContain(line);
    for (const c of certifications) {
      for (const r of c.results) if (r.status === "not_applicable") expect(docs, `${c.connector}/${r.check}`).toContain(r.reason!);
    }
  });
});
