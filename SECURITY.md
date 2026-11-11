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
- monitoring probes, SMTP delivery, vCenter/HAProxy/OPNsense integrations, and
  cron patch scheduling
- CMDB file import and host merge/overwrite behavior
- release packaging, dependency selection, and build supply chain
- privilege escalation from the controller or a managed target

Out of scope:

- vulnerabilities in a distribution's package manager or repository
- a compromised controller while the database is unlocked
- a compromised target or a malicious OS administrator
- social engineering, physical access, or stolen unlocked laptops
- denial of service caused by intentionally patching a host into a bad state

## Known limitations before production

- The **development** build uses `mutecomm/go-sqlcipher` v4.4.2. Do not deploy
  it. Production artifacts must be built with `make production`, which uses
  current SQLCipher 4.20 and the patched `third_party/go-sqlite3` driver.
- Password SSH and sudo password fallbacks are manual-run only and never
  stored. `ssh-agent`, hardware-backed keys, SSH certificates, and
  passphrase-protected key files are not implemented. Host create, update, CSV
  import, and CMDB import reject `agent` and `certificate`; scheduled
  collection only processes `auth_type=key`.
- The browser session cookie is an administrator credential. It is HttpOnly,
  SameSite=Strict, and only a SHA-256 hash is stored in SQLCipher. Protect the
  browser profile, SSH tunnel, and controller.
- Login uses Argon2id and is rate-limited. TOTP replay is rejected. Passkeys are
  bound to a `localhost` origin; `127.0.0.1` is TOTP-only because WebAuthn
  relying party IDs cannot be IP addresses.
- Account recovery is local-only: `hibp user reset` requires the database
  passphrase and access to the controller. There is no email or remote reset.
  An MFA-verified session can add/remove passkeys and replace/remove TOTP from
  **Account security**; removing the last factor is rejected. The reset command
  clears all MFA.
- Authenticated host mutations and imports record the username as the audit
  actor; internal collection records `collector`, and scheduled work records
  `scheduler`. Failed manual patch, reboot, helper-install, and host-key
  approval attempts are also audited. The audit chain is hash-chained but not
  keyed or externally anchored; a database writer can rewrite it consistently.
- The API and import paths accept an absolute `key_path` outside the configured
  key-browser roots. Filesystem permissions on the service account are the real
  boundary; give it only the intended key directory.
- Schema upgrades create and verify an automatic timestamped pre-migration
  backup in the configured backup directory, or next to the database when none
  is configured, and hard-refuse a database whose schema version is newer than
  the running binary. There is no passphrase-rekey or envelope/DEK-wrapping
  workflow.
- Backup verification opens the copy, checks migrations, and recomputes the
  full audit chain. There is no backup-without-secrets mode. Timestamped backups
  created by HIBP are pruned to the configured retention count; custom-named
  files are not.
- A fresh database is claimed through the loopback UI. Until the first account
  and MFA exist, any local user who can reach the port could claim it.
- The packaged systemd unit needs path and unlock customization:
  `ProtectHome=true` blocks `~/.ssh`, a passphrase file is required for a
  headless start, and backups outside `ReadWritePaths` are denied.
- No RBAC, durable job queue, package diff, approval workflow, approved
  playbooks, or host disabled/maintenance state. The cron scheduler is
  single-process, has bounded per-host retries but no resume/security-only
  filter, and runs only while the controller is unlocked and running.
- Patch schedules accept only key-auth hosts with a trusted host key and the
  restricted `NOPASSWD` helper. Non-eligible hosts are skipped. Apply jobs never
  reboot automatically. Per-host output in run history is capped at 16 KiB.
- Fleet monitors can emit one email per host; there is no aggregation or global
  rate limit. Audit, alert, and integration-event retention is not implemented.
  Integration poll failures are visible on the source card but not emailed.
- There is no TLS termination or supported reverse-proxy mode; the UI must stay
  on loopback. There is no Unix-socket listener, request access log, Prometheus
  endpoint, or built-in controller self-monitoring.
- Release archives are checksummed but not signed. There is no SBOM or
  provenance attestation. The installer reads `SHA256SUMS` from the same GitHub
  release, which is not independent publisher authentication. The Docker base
  image tag and SQLCipher source download are not digest/checksum-pinned. CI
  runs `govulncheck` but not `gosec`, Trivy/Grype, or a full dependency review.
- CMDB import is not a single transaction; a mid-commit failure can leave
  earlier rows applied. Regular CSV import matches duplicates by address/port,
  not CMDB ID. Missing auth metadata defaults to `key` and requires a key path;
  unsupported `agent`/`certificate` values are rejected.
- Real target, cross-distro, helper-rollout, reboot, and package-update testing
  is still required on disposable VMs before broad production use.

## Docker, monitoring, email, integration, and scheduling controls

Read-only observability, project-level Docker check/apply, monitoring rules,
SMTP email alerting, vCenter/HAProxy/OPNsense integrations, CMDB import, and
cron-based patch schedules are implemented.

- Docker socket access is root-equivalent. The controller does not connect to
  Docker directly; the root-owned helper exposes only fixed, read-only or
  explicitly confirmed actions.
- `system-info`, `metrics`, and `docker-list` are read-only. `docker-list`
  deliberately omits environment variables, command lines, mounts, and secrets.
- The collector never prompts for credentials. Scheduled collection requires
  the restricted NOPASSWD helper; password-auth hosts are collected manually.
- Docker updates are project-level Compose operations. Project names and paths
  come from Docker metadata, not arbitrary controller input. The helper accepts
  exactly one validated project argument; the `docker-check *` and
  `docker-apply *` sudoers wildcards are constrained by that validation.
- Compose files and their parent directory chain must be root-owned and not
  group/world-writable. `.env` files and build contexts must be protected by the
  operator. No automatic updates, no `down -v`, and no volume pruning. Check
  and apply are serialised with a host-wide lock and audited.
- System information remains read-only. No service start/stop/restart is exposed.
  Fleet and per-host collection settings are stored in SQLCipher.
- Monitoring definitions are administrator-only application data. Checks use
  cached host snapshots or outbound HTTP/TCP/TLS probes; they do not construct
  shell commands, open interactive SSH sessions, or change the monitored
  service. HTTP monitor URLs reject embedded credentials.
- Service monitors depend on `host_services` snapshots from the current helper.
  The controller does not clear service state when an older helper cannot report
  unit names, which avoids false outages during a rolling helper update.
- SMTP settings are stored in the encrypted `settings` scope. The password is
  never returned by the API, logged, or written to audit details. Authentication
  is allowed only over STARTTLS or implicit TLS. The test-email endpoint works
  before alerts are enabled and uses the same TLS rules.
- Alert email can contain host names, monitor names, URLs, metric values, and
  state messages. Treat the recipient list as sensitive operational data and do
  not send it to untrusted mailboxes.
- Monitoring is an alerting and visibility feature, not a remote-control plane.
  A monitoring credential must not be able to change the monitored system.
- Patch schedules are administrator-only definitions. They run the same fixed
  `check`/`apply` helper actions as manual patching, use the configured cron
  timezone and maintenance window, and only target hosts with key auth and a
  trusted host key. Concurrency is bounded per schedule, failed hosts can be
  retried a configured number of times, and every host attempt is written to
  run history and the audit log. Apply jobs do not reboot automatically. The
  scheduler is not a durable job queue: an interrupted run is not resumed, and
  the process must be unlocked and running. Manual patch, reboot, helper
  bootstrap, and scheduled patch operations share a process-local per-host
  lock; a second operation on the same host is rejected or skipped. Multiple
  controller processes must not share one database.
- SMTP is also used for schedule summaries. A local Postfix relay with no
  authentication is supported over a reachable TCP socket, but must be
  restricted to trusted sources; plain SMTP has no transport encryption.
- External integrations are read-only:
  - vCenter uses a dedicated read-only account over HTTPS, retrieves active
    triggered alarms for all managed entities, and never syncs inventory or
    acknowledges, clears, or changes vCenter objects. TLS verification is on by
    default; the opt-out is intentionally explicit for self-signed labs.
  - HAProxy reads the stats HTTP CSV endpoint with optional Basic auth. It never
    uses the admin socket and never changes runtime state.
  - OPNsense reads the gateway status endpoint with an API key/secret for a
    least-privilege user.
- Integration credentials are stored only in the SQLCipher `settings` scopes and
  are never returned by the API, logged, or written to audit details. Each
  integration can use SMTP default recipients or its own recipient list.
- Integration polling originates from the controller and can reach internal
  addresses by design. Only administrators can define endpoints; deploy the
  controller on an appropriately restricted network. The URL validators allow
  HTTP for HAProxy/OPNsense, so use HTTPS for credentialed endpoints. The
  runtime has no telemetry or internet requirement; installation and updates
  are the only external transfer steps.
- CMDB import is read-only and file-based. HIBP never opens the CMDB database and
  never writes back. Imports are bounded (10 MiB, 5,000 records), validated, and
  previewed before commit. Imported data cannot contain HIBP secrets, and host
  keys are still approved only after an independent fingerprint check.
- SMTP credentials, vCenter credentials, and API tokens are stored only in the
  SQLCipher database and are never returned by the API, logged, or written to
  audit details. Use TLS for SMTP and read-only accounts for vCenter/HAProxy/
  OPNsense.

## Operational guidance

- Use a unique database passphrase and full-disk encryption.
- Complete first-run account and MFA setup immediately; until then any local
  user who can reach the loopback UI could claim the administrator account.
- If using the packaged systemd unit, create `/etc/hibp/ssh`,
  `/etc/hibp/ssh/config`, and `/etc/hibp/db.passphrase` with the documented
  ownership/modes, or adjust the unit. Keep backups under `/var/lib/hibp` or add
  the backup directory to `ReadWritePaths`.
- Keep the database, backups, and SSH keys at mode `0600`.
- Verify host-key fingerprints through an independent channel.
- Use a check-only schedule on a canary host before any apply schedule; keep
  schedule concurrency low and review Recent runs and the audit log.
- If using interactive unlock, keep the server in a persistent console/tmux
  session. Schedules, collection, and monitoring stop when the process stops.
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
- Review any future approved playbooks before activation. Arbitrary shell is
  intentionally disabled in this release.
