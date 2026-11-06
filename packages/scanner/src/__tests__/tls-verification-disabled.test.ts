import { describe, expect, it } from "vitest";
import { tlsVerificationDisabledMatcher } from "../matchers/tls-verification-disabled.js";

const m = tlsVerificationDisabledMatcher;

describe("tls-verification-disabled matcher", () => {
  it("reports each idiom in a file with several distinct disables", () => {
    const src = `
const agent = new https.Agent({ rejectUnauthorized: false });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const url = "postgres://user:pass@db:5432/app?sslmode=disable";
`;
    const matches = m.match(src, "src/client.ts");
    const labels = matches.map((x) => x.matchedPattern);
    expect(labels).toContain("rejectUnauthorized: false");
    expect(labels.join(" ")).toContain("NODE_TLS_REJECT_UNAUTHORIZED");
    expect(labels.join(" ")).toContain("sslmode=disable");
    expect(matches.length).toBe(3);
  });

  it("matches spacing and assignment variants", () => {
    expect(m.match(`opts = { rejectUnauthorized:false }`, "src/a.js").length).toBe(1);
    expect(m.match(`resp = session.get(url, verify = False)`, "src/a.py").length).toBe(1);
    expect(m.match(`https.globalAgent.options.rejectUnauthorized = false`, "src/a.js").length).toBe(
      1,
    );
  });

  it("does not fire verify=False on non-HTTP kwargs", () => {
    expect(m.match(`claims = jwt.decode(encoded, verify=False)`, "src/auth.py")).toEqual([]);
    expect(m.match(`t = ctx.findroot(f, ab, solver='illinois', verify=False)`, "src/m.py")).toEqual(
      [],
    );
    expect(m.match(`@array_function_dispatch(_dispatcher, verify=False)`, "src/np.py")).toEqual([]);
  });

  it("does not flag verification-enabled configurations", () => {
    const src = `
const agent = new https.Agent({ rejectUnauthorized: true });
conf := &tls.Config{InsecureSkipVerify: false}
resp = requests.get(url, verify=True)
DATABASE_URL=postgres://user:pass@db:5432/app?sslmode=require
`;
    expect(m.match(src, "src/client.ts")).toEqual([]);
  });

  it("skips test files across ecosystems", () => {
    const bad = `const agent = new https.Agent({ rejectUnauthorized: false });`;
    expect(m.match(bad, "src/client.test.ts")).toEqual([]);
    expect(m.match(`conf := &tls.Config{InsecureSkipVerify: true}`, "pkg/client_test.go")).toEqual(
      [],
    );
    expect(m.match(`resp = requests.get(url, verify=False)`, "app/test_client.py")).toEqual([]);
    expect(m.match(`resp = requests.get(url, verify=False)`, "app/client_test.py")).toEqual([]);
    expect(m.match(`http.verify_mode = OpenSSL::SSL::VERIFY_NONE`, "lib/client_spec.rb")).toEqual(
      [],
    );
    expect(m.match(bad, "spec/support/helper.rb")).toEqual([]);
    expect(m.match(`resp = requests.get(url, verify=False)`, "tests/conftest.py")).toEqual([]);
  });

  it("does not flag curl without insecure flags or unrelated -k-like tokens", () => {
    expect(m.match(`RUN curl -fsSL https://example.com/install.sh | sh`, "Dockerfile")).toEqual([]);
    expect(m.match(`curl -s -o /tmp/kubeconfig https://example.com`, "deploy.sh")).toEqual([]);
  });
});
