import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isHighEntropy, scanFile, scanTree, shannon } from "../src/scan.ts";

/** Deterministic fake keys (no real credentials). */
const AWS_KEY = `AKIA${Array.from({ length: 16 }, (_, i) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[(i * 7 + 3) % 36]).join("")}`;
const GOOGLE_KEY = `AIza${Array.from({ length: 35 }, (_, i) => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"[(i * 11 + 5) % 64]).join("")}`;
const GITHUB_TOKEN = `ghp_${Array.from({ length: 40 }, (_, i) => "abcdef0123456789"[(i * 3 + 1) % 16]).join("")}`;
const STRIPE_KEY = `sk_live_${Array.from({ length: 24 }, (_, i) => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[(i * 7 + 3) % 62]).join("")}`;
const FAKE_AWS = "AKIA-this-is-not-a-real-key-format";

const PEM = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "MIIBOgIBAAJBAK6p9SKJJvN6A9XcB3Wrj0mK5rsb4JZ8q3mTQ/F8w1vJKrP0g2N7",
  "Qj7Pq3m8YhLm4Zx2RvQn1OzJk0XvLq8fDhZ6zYgW2pJqYh4NpZf3LbQ8vXjLk5Gz",
  "-----END RSA PRIVATE KEY-----",
].join("\n");

const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

let dir: string;
let nested: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "zh-secret-"));
  nested = join(dir, "config", "nested");
  await mkdir(nested, { recursive: true });
  await mkdir(join(dir, "node_modules", "dep"), { recursive: true });
  await mkdir(join(dir, ".git"), { recursive: true });
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("entropy helpers", () => {
  it("shannon: uniform strings have maximal entropy", () => {
    expect(shannon("aaaa")).toBe(0);
    expect(shannon("abcd")).toBe(2);
    expect(shannon("")).toBe(0);
    expect(shannon("abcdefghijklmnopqrstuvwxyz0123456789")).toBeGreaterThan(5);
  });

  it("isHighEntropy gates on length and density", () => {
    expect(isHighEntropy(AWS_KEY)).toBe(true);
    expect(isHighEntropy("abcdefghij")).toBe(false);
    expect(isHighEntropy("aaaaaaaaaaaaaaaa")).toBe(false);
    expect(isHighEntropy("short", 16)).toBe(false);
  });
});

describe("scanFile", () => {
  it("detects an AWS key, Google key, GitHub token, Stripe key and JWT in one file", async () => {
    const f = join(nested, "creds.txt");
    await writeFile(
      f,
      `aws_access_key_id = ${AWS_KEY}\ngcp= ${GOOGLE_KEY}\ntoken=${GITHUB_TOKEN}\nsk=${STRIPE_KEY}\njwt=${JWT}\n`
    );
    const kinds = (await scanFile(f)).map((m) => m.kind);
    expect(kinds).toEqual(
      expect.arrayContaining(["aws-access-key", "google-api-key", "github-token", "stripe-secret-key", "jwt"])
    );
  });

  it("reports 1-based line and column", async () => {
    const f = join(dir, "one.txt");
    await writeFile(f, `hello world\n  ${AWS_KEY}\n`);
    const match = (await scanFile(f))[0];
    expect(match.line).toBe(2);
    expect(match.column).toBe(3);
    expect(match.matched).toBe(AWS_KEY);
    expect(match.file).toBe(f);
  });

  it("ignores format-shaped-but-fake tokens", async () => {
    const f = join(dir, "fake.txt");
    await writeFile(f, `${FAKE_AWS}\nAKIA1234567890abcde\n`);
    expect(await scanFile(f)).toEqual([]);
  });

  it("detects PEM and OpenSSH private key blocks", async () => {
    const f = join(dir, "id_rsa.pem");
    await writeFile(
      f,
      `${PEM}\n\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAMAAAAD\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n`
    );
    const kinds = (await scanFile(f)).map((m) => m.kind);
    expect(kinds).toContain("private-key");
    expect(kinds).toContain("openssh-private-key");
  });

  it("returns [] for binary files", async () => {
    const f = join(dir, "blob.bin");
    await writeFile(f, Buffer.from(`\u0000\u0001\u0002${AWS_KEY}\u0000`, "binary"));
    expect(await scanFile(f)).toEqual([]);
  });

  it("return [] for files without secrets", async () => {
    const f = join(dir, "clean.ts");
    await writeFile(f, "export const x = 1;\n// nothing sensitive\n");
    expect(await scanFile(f)).toEqual([]);
  });
});

describe("scanTree", () => {
  it("walks nested directories and returns relative paths", async () => {
    await writeFile(join(dir, "a.txt"), AWS_KEY);
    await writeFile(join(dir, "config", "nested", "b.txt"), GITHUB_TOKEN);
    const matches = await scanTree(dir);
    expect(matches.map((m) => m.file).sort()).toEqual(["a.txt", "config/nested/b.txt"]);
    expect(matches.map((m) => m.kind).sort()).toEqual(["aws-access-key", "github-token"]);
  });

  it("skips .git, node_modules, dist, .next and package-lock.json by default", async () => {
    for (const [rel, content] of [
      ["node_modules/dep/x.js", AWS_KEY],
      [".git/config", GITHUB_TOKEN],
      ["dist/bundle.js", GOOGLE_KEY],
      [".next/cache.js", GITHUB_TOKEN],
      ["package-lock.json", AWS_KEY],
    ] as const) {
      const full = join(dir, rel);
      if (rel.includes("/")) await mkdir(join(dir, rel.split("/").slice(0, -1).join("/")), { recursive: true });
      await writeFile(full, content);
    }
    await writeFile(join(dir, "keep.txt"), AWS_KEY);
    const matches = await scanTree(dir);
    expect(matches).toHaveLength(1);
    expect(matches[0].file).toBe("keep.txt");
  });

  it("respects custom ignore entries on top of the defaults", async () => {
    const sub = join(dir, "tmp");
    await mkdir(sub);
    await writeFile(join(sub, "copy.js"), AWS_KEY);
    await writeFile(join(dir, "real.txt"), AWS_KEY);
    const matches = await scanTree(dir, { ignore: ["tmp"] });
    expect(matches.map((m) => m.file)).toEqual(["real.txt"]);
  });

  it("ignores symlinked dirs (no cycles)", async () => {
    await writeFile(join(nested, "real.txt"), AWS_KEY);
    await (await import("node:fs/promises")).symlink(dir, join(dir, "loop"));
    const matches = await scanTree(dir);
    expect(matches.map((m) => m.file)).toEqual(["config/nested/real.txt"]);
  });
});