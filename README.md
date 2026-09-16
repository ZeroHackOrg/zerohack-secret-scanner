<div align="center">

```
 ____________ _____   ____  _    _          _____ _  __
|___  /  ____|  __ \ / __ \| |  | |   /\   / ____| |/ /
   / /| |__  | |__) | |  | | |__| |  /  \ | |    | ' / 
  / / |  __| |  _  /| |  | |  __  | / /\ \| |    |  <  
 / /__| |____| | \ \| |__| | |  | |/ ____ \ |____| . \ 
/_____|______|_|  \_\____/|_|  |_/_/    \_\_____|_|\_\

              Fortifying the Digital Frontier
```

# @zerohack/secret-scanner · `zh-secret`

**Entropy + pattern secret scanner for source trees — AWS, GCP, GitHub, Stripe, JWT, PEM**

[![License](https://img.shields.io/badge/license-Apache--2.0-00B0BD?style=for-the-badge)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6?style=for-the-badge&logo=typescript&logoColor=white)](tsconfig.json)
[![Zero Budget](https://img.shields.io/badge/cost-%240-00b894?style=for-the-badge)](https://zerohack.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-00B0BD?style=for-the-badge)](CONTRIBUTING.md)

**Part of the [ZeroHack](https://zerohack.org) Geek Tools ecosystem**
Category: `devsecops` · `security` · `secrets` · `scan`

</div>

---

> **⚡ Zero Budget. Zero Cloud Dependencies. Pure Local Power.**

---

## What It Does

Offline secret scanner: detects AWS keys, Google API keys, GitHub tokens,
Slack tokens, Stripe secret keys, JWTs and PEM/OpenSSH private keys.
Regex-driven with a Shannon-entropy gate, deterministic, unit-testable,
never touches the network.

---

## Quick Start

### Standalone

```bash
git clone https://github.com/ZeroHackOrg/zerohack-secret-scanner.git
cd zerohack-secret-scanner && npm install
npx tsx src/bin.ts scan ./prod --json
```

### Standalone Resolution

```bash
git clone https://github.com/ZeroHackOrg/zerohack-shared.git
cd zerohack-shared && npm install && npm link
cd ../zerohack-secret-scanner && npm link @zerohack/shared
```

---

## Commands

| Command | Description |
|---|---|
| `zh-secret scan <path> [--json]` | Scan a file or directory tree |
| `zh-secret scan <path> --ignore dist build` | Extend the ignore list |

Text mode prints `FILE:LINE:COL:KIND:MASKED`; `--json` prints full
`SecretMatch` objects. Exit code is `1` when any secret is found
(`grep`-style).

---

## Patterns Detected

| kind | regex |
| --- | --- |
| `aws-access-key` | `AKIA[0-9A-Z]{16}` |
| `google-api-key` | `AIza[0-9A-Za-z_-]{35}` |
| `github-token` | `gh[pousr]_[0-9A-Za-z]{36,255}` |
| `slack-token` | `xox[baprs]-[0-9A-Za-z]{16,}` |
| `stripe-secret-key` | `sk_live_[0-9a-zA-Z]{24}` |
| `jwt` | `eyJ...\.eyJ...\.eyJ...` |
| `private-key` | `-----BEGIN … PRIVATE KEY-----` block |
| `openssh-private-key` | `-----BEGIN OPENSSH PRIVATE KEY-----` block |

All single-line matches are gated on `isHighEntropy`.

---

## Design Notes

- **Deterministic & pure**: only `node:fs` + regex; no randomness, no
  network. Tests build fixtures under `os.tmpdir()` and clean them up.
- **Entropy gate**: `shannon()` + `isHighEntropy(token, minLen=16)`
  (~3.5 bits/char) must both pass for single-line token patterns, so
  format-shaped-but-repetitive strings are ignored. PEM blocks are gated
  on structure only.
- **Binary detection**: a NUL byte in the first 8KB marks a file binary
  and it is skipped. Symlinks are never followed (no cycles).
- **Default ignores**: `.git`, `node_modules`, `dist`, `.next`,
  `package-lock.json` — extendable via `--ignore` / `{ ignore }`.

---

## Env

None — all tools are zero-dependency, zero-config, and run offline.

---

## Tests

```bash
npm run typecheck --workspace @zerohack/secret-scanner
npm run test    --workspace @zerohack/secret-scanner
```

---

## Architecture

```
zerohack-secret-scanner/
├── src/
│   ├── bin.ts          # CLI entrypoint (commander)
│   ├── index.ts        # Re-exports
│   └── scan.ts         # Pattern table, shannon entropy, scanTree/scanFile
├── test/
│   └── scan.test.ts    # Unit tests (vitest)
├── package.json
├── tsconfig.json
├── README.md
├── LICENSE             # Apache-2.0
├── SECURITY.md
├── CONTRIBUTING.md
└── CODE_OF_CONDUCT.md
```

**Design principles:**
- Pure core: no randomness, no network, deterministic output.
- Entropy gate avoids false positives on format-shaped strings.
- Scans are relative-path based for stable output.

---

## Security

Never touches the network. Does not send your secrets anywhere. Use in CI
to prevent secrets from ever being committed.

For vulnerability reports, see [SECURITY.md](SECURITY.md).

---

## Related Packages

| Package | Binary | What It Does |
|---|---|---|
| [@zerohack/shared](https://github.com/ZeroHackOrg/zerohack-shared) | — | Types, schemas, catalog |
| [@zerohack/cli](https://github.com/ZeroHackOrg/zerohack-cli) | `zh` | Unified CLI |
| [@zerohack/supalite-api](https://github.com/ZeroHackOrg/zerohack-supalite-api) | `zh-api` | PostgREST API |
| [@zerohack/pal](https://github.com/ZeroHackOrg/zerohack-pal) | `zh-pal` | Local AI assistant |
| [@zerohack/honeypot](https://github.com/ZeroHackOrg/zerohack-honeypot) | `zh-honeypot` | Honeypot |
| [@zerohack/osint-cli](https://github.com/ZeroHackOrg/zerohack-osint-cli) | `zh-osint` | OSINT tools |
| [@zerohack/ssh-hardener](https://github.com/ZeroHackOrg/zerohack-ssh-hardener) | `zh-ssh` | SSH auditor |
| [@zerohack/recon-bot](https://github.com/ZeroHackOrg/zerohack-recon-bot) | `zh-recon` | Recon automation |
| [@zerohack/log-analyzer](https://github.com/ZeroHackOrg/zerohack-log-analyzer) | `zh-log` | Log forensics |
| [@zerohack/ctf-lab](https://github.com/ZeroHackOrg/zerohack-ctf-lab) | `zh-lab` | CTF lab runner |
| [@zerohack/ctf-automation](https://github.com/ZeroHackOrg/zerohack-ctf-automation) | `zh-ctf` | CTF solver |
---

## Community

- **Issues:** [GitHub Issues](https://github.com/ZeroHackOrg/zerohack-secret-scanner/issues)
- **PRs:** [Pull Requests](https://github.com/ZeroHackOrg/zerohack-secret-scanner/pulls)
- **Security:** [SECURITY.md](SECURITY.md)
- **Platform:** [zerohack.org](https://zerohack.org)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Read our [Code of Conduct](CODE_OF_CONDUCT.md) first.

## License

[Apache-2.0](LICENSE) — Copyright 2026 ZeroHack Security