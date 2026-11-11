# Security policy

HIBP is a privileged remote administration tool. It can run package-manager
operations as root on managed Linux hosts. Treat the controller and its database
as high-value assets.

## Supported versions

Only the latest release is supported with security fixes. The `main` branch is
the development branch and may contain unreleased changes.

## Reporting a vulnerability

Do not open a public issue with a working exploit, credentials, private keys, or
host details.

Use GitHub's private vulnerability reporting for this repository:

https://github.com/RogerBergling/HIBP/security/advisories/new

If private reporting is unavailable, contact the maintainer through the GitHub
profile and ask for a private channel.

Include:

- affected version or commit,
- impact and affected component,
- reproduction steps or a proof of concept,
- whether the issue requires a trusted host, a local user, or network access,
- any suggested mitigation.

## Scope

In scope:

- SQLCipher database handling, key derivation, sidecar handling, backup/restore
- browser UI authentication, CSRF, XSS, local API exposure
- SSH host-key verification, key handling, command construction
- sudo helper argument validation and privilege boundaries
- audit-chain integrity and log redaction
- import/export parsing, CSV injection, path traversal
- privilege escalation from the controller or a managed target

Out of scope:

- vulnerabilities in a distribution's package manager or repository
- a compromised controller while the database is unlocked
- a compromised target or a malicious OS administrator
- social engineering, physical access, or stolen unlocked laptops
- denial of service caused by intentionally patching a host into a bad state

## Known M1 security debt

- The **development** build uses `mutecomm/go-sqlcipher` v4.4.2. Do not deploy
  it. Production artifacts must be built with `make production`, which uses
  current SQLCipher 4.20 and the patched `third_party/go-sqlite3` driver.
- Password SSH and sudo password fallbacks are manual-run only and never
  stored. Vault-backed scheduled password authentication, RBAC, external audit
  anchoring, TPM-sealed keys, agent mode, and signed playbooks are not
  implemented yet.
- The browser session cookie is an administrator credential. It is HttpOnly,
  SameSite=Strict, and only a SHA-256 hash is stored in SQLCipher. Protect the
  browser profile, SSH tunnel, and controller.
- Login uses Argon2id and is rate-limited. TOTP replay is rejected. Passkeys are
  bound to a `localhost` origin; `127.0.0.1` is TOTP-only because WebAuthn
  relying party IDs cannot be IP addresses.
- Account recovery is local-only: `hibp user reset` requires the database
  passphrase and access to the controller. There is no email or remote reset.

## Docker and monitoring controls

Phase 1 is implemented as read-only observability. The mutating Docker and
alerting controls below apply to the next phases.

- Docker socket access is root-equivalent. The controller does not connect to
  Docker directly; the root-owned helper exposes only fixed, read-only or
  explicitly confirmed actions.
- `system-info`, `metrics`, and `docker-list` are read-only. `docker-list`
  deliberately omits environment variables, command lines, mounts, and secrets.
- The collector never prompts for credentials. Scheduled collection requires
  the restricted NOPASSWD helper; password-auth hosts are collected manually.
- Docker updates will be project-level Compose operations. Project names and
  paths come from Docker metadata, not arbitrary controller input. Compose
  files, `.env` files, and build contexts must be root-owned and not
  group/world-writable. No automatic updates, no `down -v`, and no volume
  pruning.
- System information remains read-only. No service start/stop/restart is exposed
  in the first monitoring release. Fleet and per-host collection settings are
  stored in SQLCipher.
- SMTP credentials, vCenter credentials, and API tokens are stored only in the
  SQLCipher database and are never returned by the API, logged, or written to
  audit details. Use TLS for SMTP and read-only accounts for vCenter/HAProxy/
  OPNsense.
- Monitoring is an alerting and visibility feature, not a remote-control plane.
  A monitoring credential must not be able to change the monitored system.

## Operational guidance

- Use a unique database passphrase and full-disk encryption.
- Keep the database, backups, and SSH keys at mode `0600`.
- Verify host-key fingerprints through an independent channel.
- Do not use `NOPASSWD: ALL`; use the narrow helper rule.
- The reboot action is destructive. HIBP requires explicit confirmation in the
  API and UI and runs only the fixed helper action. It never reboots
  automatically; later/scheduled reboots are part of the scheduler work.
- The local SSH config reader returns aliases, hostnames, users, ports, and key
  paths only. It never returns private key contents. Treat the config path and
  the imported metadata as sensitive.
- Remote helper installation uploads the controller binary to the target. Use
  the static release build, keep the host key pinned, and use the Setup flow
  only against hosts you intend to manage.
- Keep at least one encrypted backup off the controller and test restores.
- Treat the session cookie, the SSH tunnel, and the controller as credentials.
- Review playbooks before approval. Arbitrary shell is intentionally disabled.
