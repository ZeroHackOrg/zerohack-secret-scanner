/** Deterministic, offline secret scanning: entropy helpers, pattern specs,
 *  a single-file scanner and a recursive tree walker. No network, no
 *  external crypto — everything is node:fs + plain regex. */

import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

export interface SecretMatch {
  file: string;
  line: number;
  column: number;
  kind: string;
  matched: string;
}

export interface ScanOptions {
  ignore?: string[];
}

/** Directories and files skipped by default, mirroring what you never want
 *  to ship or scan: VCS internals, build/dependency trees and lockfiles. */
export const DEFAULT_IGNORES: readonly string[] = [
  ".git",
  "node_modules",
  "dist",
  ".next",
  "package-lock.json",
];

/** Shannon entropy (bits per character) of a string. 0 for empty input. */
export function shannon(s: string): number {
  const t = String(s ?? "");
  if (t.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of t) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let e = 0;
  for (const c of counts.values()) {
    const p = c / t.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/** A token is "high entropy" when it is long enough (>= minLen) and dense
 *  enough (~3.5 bits/char, the zip-file/random-string ballpark). */
export function isHighEntropy(token: string, minLen = 16): boolean {
  const t = String(token ?? "");
  return t.length >= minLen && shannon(t) >= HIGH_ENTROPY_THRESHOLD;
}

export const HIGH_ENTROPY_THRESHOLD = 3.5;

/* ------------------------------ pattern specs --------------------------- */

export interface PatternSpec {
  kind: string;
  re: RegExp;
  /** Require the matched token to pass the entropy gate. */
  entropyGate: boolean;
  /** Match may span multiple lines (e.g. PEM blocks). */
  multiline: boolean;
}

const AWS_ACCESS_KEY = "AKIA[0-9A-Z]{16}";
const GOOGLE_API_KEY = "AIza[0-9A-Za-z_-]{35}";
const GITHUB_TOKEN = "gh[pousr]_[0-9A-Za-z]{36,255}";
const SLACK_TOKEN = "xox[baprs]-[0-9A-Za-z]{16,}";
const STRIPE_SECRET = "sk_live_[0-9a-zA-Z]{24}";
const JWT = "eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}";

const PEM_HEADER = "-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----";
const PEM_FOOTER = "-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----";

/** Well-known high-value secret shapes. Single-line specs are checked per
 *  line (so columns are exact); multiline specs check the whole file. */
export const PATTERNS: readonly PatternSpec[] = [
  { kind: "aws-access-key", re: new RegExp(`\\b${AWS_ACCESS_KEY}\\b`), entropyGate: true, multiline: false },
  { kind: "google-api-key", re: new RegExp(`\\b${GOOGLE_API_KEY}\\b`), entropyGate: true, multiline: false },
  { kind: "github-token", re: new RegExp(`\\b${GITHUB_TOKEN}\\b`), entropyGate: true, multiline: false },
  { kind: "slack-token", re: new RegExp(`\\b${SLACK_TOKEN}\\b`), entropyGate: true, multiline: false },
  { kind: "stripe-secret-key", re: new RegExp(`\\b${STRIPE_SECRET}\\b`), entropyGate: true, multiline: false },
  { kind: "jwt", re: new RegExp(`\\b${JWT}\\b`), entropyGate: true, multiline: false },
  { kind: "private-key", re: new RegExp(`${PEM_HEADER}[\\s\\S]*?${PEM_FOOTER}`), entropyGate: false, multiline: true },
  {
    kind: "openssh-private-key",
    re: new RegExp("-----BEGIN OPENSSH PRIVATE KEY-----[\\s\\S]*?-----END OPENSSH PRIVATE KEY-----"),
    entropyGate: false,
    multiline: true,
  },
];

function cloneRe(re: RegExp): RegExp {
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  return new RegExp(re.source, flags);
}

function indexToLineCol(content: string, index: number): { line: number; column: number } {
  let line = 1;
  let last = 0;
  for (let i = 0; i < index; i++) {
    if (content.charCodeAt(i) === 10) {
      line++;
      last = i + 1;
    }
  }
  return { line, column: index - last + 1 };
}

function matchesFrom(content: string, pathForMatch: string, spec: PatternSpec): SecretMatch[] {
  const re = cloneRe(spec.re);
  const out: SecretMatch[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const token = m[0];
    if (spec.entropyGate && !isHighEntropy(token)) {
      if (m.index === re.lastIndex) re.lastIndex++;
      continue;
    }
    out.push({ file: pathForMatch, ...indexToLineCol(content, m.index), kind: spec.kind, matched: token });
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

/** Scan a single file's plaintext `content`, tagging matches with the
 *  `file` label provided. Exported so callers can scan in-memory buffers. */
export function scanContent(content: string, file: string): SecretMatch[] {
  const out: SecretMatch[] = [];
  const lines = content.split(/\r?\n/);
  for (const spec of PATTERNS) {
    if (spec.multiline) {
      out.push(...matchesFrom(content, file, spec));
    } else {
      for (let i = 0; i < lines.length; i++) {
        const re = cloneRe(spec.re);
        let m: RegExpExecArray | null;
        while ((m = re.exec(lines[i])) !== null) {
          const token = m[0];
          if (spec.entropyGate && !isHighEntropy(token)) {
            if (m.index === re.lastIndex) re.lastIndex++;
            continue;
          }
          out.push({ file, line: i + 1, column: m.index + 1, kind: spec.kind, matched: token });
          if (m.index === re.lastIndex) re.lastIndex++;
        }
      }
    }
  }
  return out.sort((a, b) => a.line - b.line || a.column - b.column || a.kind.localeCompare(b.kind));
}

/** True when the file is "binary": a NUL byte appears in the first 8KB. */
export async function looksBinary(filePath: string): Promise<boolean> {
  const fd = await readFile(filePath);
  const head = fd.subarray(0, Math.min(8192, fd.length));
  return head.includes(0);
}

/** Scan one file from disk. Returns [] for missing/binary files. */
export async function scanFile(filePath: string): Promise<SecretMatch[]> {
  if (await looksBinary(filePath)) return [];
  const content = await readFile(filePath, "utf8");
  return scanContent(content, filePath);
}

async function collectFiles(dir: string, ignoreSet: ReadonlySet<string>, out: string[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (ignoreSet.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      await collectFiles(full, ignoreSet, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
}

/** Recursively walk `root` (skipping default ignores + any custom ones, and
 *  binary files) and return every secret match. Match `file` paths are
 *  relative to `root` for stable output. */
export async function scanTree(root: string, opts: ScanOptions = {}): Promise<SecretMatch[]> {
  const ignoreSet = new Set<string>([...DEFAULT_IGNORES, ...(opts.ignore ?? [])]);
  const files: string[] = [];
  await collectFiles(root, ignoreSet, files);
  const matches: SecretMatch[] = [];
  for (const file of files) {
    if (await looksBinary(file)) continue;
    const content = await readFile(file, "utf8");
    const rel = relative(resolve(root), resolve(file));
    matches.push(...scanContent(content, rel));
  }
  return matches;
}