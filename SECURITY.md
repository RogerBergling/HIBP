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
- monitoring probes, SMTP delivery, durable manual jobs, package deployment,
  and cron patch scheduling
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
- Password SSH and sudo password fallbacks are interactive per-host actions and
  are never stored. The first accepted sudo password may be reused in browser
  memory for other interactive hosts with the same SSH username; it is never
  persisted and is discarded after a wrong password, sign-out, or tab close.
  Selected-host and fleet jobs require key authentication and non-interactive
  sudo; they never receive a prompted password. `ssh-agent`, hardware-backed
  keys, SSH certificates, and passphrase-protected key files are not
  implemented. Host create, update, CSV import, and CMDB import accept
  `auth_type=agent` and `auth_type=network` for monitoring-only hosts and
  reject `certificate`; scheduled SSH collection and background jobs only
  process `auth_type=key` hosts. `network` hosts use SNMP/syslog only. Agent hosts use a per-host bearer token and cannot run SSH actions.
- `ProxyJump` is single-hop only. Multi-hop chains, interactive bastion
  authentication, SSH agent forwarding, and a jump host behind another jump are
  not supported.
- The browser session cookie is an administrator credential. It is HttpOnly,
  SameSite=Strict, and only a SHA-256 hash is stored in SQLCipher. Protect the
  browser profile, SSH tunnel (or LAN HTTPS session), and controller.
- Login uses Argon2id and is rate-limited. TOTP replay is rejected. Passkeys
  are bound to the `localhost` origin or the configured LAN HTTPS public URL.
  `127.0.0.1` and IP-address LAN URLs are TOTP-only because WebAuthn relying
  party IDs cannot be IP addresses.
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
- A fresh database is claimed through the loopback UI or the configured LAN
  HTTPS UI. Until the first account and MFA exist, anyone who can reach that
  listener could claim it.
- The packaged systemd unit needs path and unlock customization:
  `ProtectHome=true` blocks `~/.ssh`, a passphrase file is required for a
  headless start, and backups outside `ReadWritePaths` are denied.
- No RBAC, approval workflow, approved playbooks, or host
  disabled/maintenance state. Manual operations use a durable job queue, but
  the cron scheduler remains a separate single-process engine with bounded
  per-host retries and no security-only filter. Both run only while the
  controller is unlocked and running.
- Patch schedules accept only key-auth hosts with a trusted host key and the
  restricted `NOPASSWD` helper. Non-eligible hosts are skipped. A schedule can
  opt in to a reboot after a successful apply when the fixed `reboot-check`
  reports it is required; the default is no reboot. HIBP does not wait for or
  verify the rebooted host. Per-host output in run history is capped at 16 KiB.
- Fleet monitors can emit one email per host; there is no aggregation or global
  rate limit. Audit, alert, and job retention is not implemented.
- The UI has built-in TLS for the optional LAN HTTPS mode and an explicit
  trusted-proxy mode for an existing TLS terminator. The default remains
  loopback-only. Built-in LAN mode requires `--tls-cert`, `--tls-key`, and
  `--public-url`; trusted-proxy mode requires `--trust-proxy`, a public HTTPS
  URL, and `--trusted-proxy-cidrs` restricted to the proxy source. The listener
  accepts only the configured hostname plus loopback Host headers. There is no
  Unix-socket listener, request access log, Prometheus endpoint, or built-in
  controller self-monitoring.
- Release archives are checksummed but not signed. There is no SBOM or
  provenance attestation. The installer reads `SHA256SUMS` from the same GitHub
  release, which is not independent publisher authentication. The Docker base
  image tag and SQLCipher source download are not digest/checksum-pinned. CI
  runs `govulncheck` but not `gosec`, Trivy/Grype, or a full dependency review.
- CMDB import is not a single transaction; a mid-commit failure can leave
  earlier rows applied. Regular CSV import matches duplicates by address/port,
  not CMDB ID. Missing auth metadata defaults to `key` and requires a key path;
  unsupported `certificate` values are rejected, while `agent` is accepted for
  monitoring-only hosts.
- Real target, cross-distro, helper-rollout, reboot, and package-update testing
  is still required on disposable VMs before broad production use.

## Docker, monitoring, email, jobs, and scheduling controls

Read-only observability, project-level Docker check/apply, monitoring rules,
SMTP email alerting, durable manual jobs, package deployment, CMDB import, and
cron-based patch schedules are implemented.

- Docker socket access is root-equivalent. The controller does not connect to
  Docker directly; the root-owned helper exposes only fixed, read-only or
  explicitly confirmed actions.
- `system-info`, `metrics`, and `docker-list` are read-only. `docker-list`
  deliberately omits environment variables, command lines, mounts, and secrets.
- The collector never prompts for credentials. Scheduled collection requires
  the restricted NOPASSWD helper; password-auth hosts are collected manually.
- Service baseline exclusions, per-host baseline disable, and baseline resets
  are authenticated admin actions and are audited. Excluding a unit suppresses
  failed and missing alerts for that host; review the host Services tab and
  audit entries when alert coverage matters.
- A `docker.container` monitor with target `*` intentionally treats stopped and
  exited containers as critical. Use it only where every container must stay
  running; one-shot jobs need a different monitor type or a named container.
- Agent hosts use a per-host bearer token. Only a SHA-256 hash is stored; the
  token is shown once and can be rotated or revoked. Agent endpoints accept
  heartbeat, snapshot, and normalized event data for the bound host only; they
  cannot execute commands. The current MVP does not use mTLS, so deploy agents
  over HTTPS and restrict the endpoint with a private network/firewall policy.
- Windows agent support is monitoring-only. It does not perform Windows Update
  patching, arbitrary commands, or Windows runbooks.
- Network-device hosts use `auth_type=network` and are read-only. They have no
  SSH actions. SNMP polling uses v1/v2c in the current MVP; the community string
  is stored in the encrypted database and masked in API responses. SNMPv2c
  sends the community in clear text, so restrict UDP 161 to the controller.
- Clearing security/service events or alert history is an authenticated action
  and is written to the audit log. Audit entries remain append-only and cannot
  be cleared from the UI.
- Imported MIB files are untrusted text. HIBP caps file size, total library
  size, and resolved symbol count; parses MIBs in-process; and never executes
  MIB content. MIB import and deletion are authenticated and audited.
- Syslog policies can reclassify or suppress noisy events but never delete them.
  Suppressed events remain in the encrypted database and can be viewed with
  **Show suppressed**. Policy changes are audited. Critical events,
  authentication failures, security threats, and protected kernel failures
  cannot be suppressed or downgraded.
- Monitor acknowledgements keep the current critical/warning state visible,
  suppress repeat email notifications, and clear automatically on recovery or
  severity escalation. Ack/unack actions are audited.
- Event acknowledgements only mark a retained event as reviewed. They never
  change severity, category, suppression, retention, monitor counts, or
  guardrails. Dashboard severity cards and the sidebar count show unreviewed
  events, while acknowledged events remain retained, listed, and reported
  separately. Ack/unack actions are audited; events remain until explicitly
  cleared.
- The syslog receiver is disabled by default. When enabled it binds the
  configured address and accepts events only from source IPs mapped to a
  managed host (the host address plus its configured extra source IPs). Syslog
  is unauthenticated and spoofable; bind it to the LAN, firewall it to the
  device/network CIDR, and never expose it publicly.
- `snmp.value` monitors compare numeric scalar OID values. `snmp.poll` alerts on
  failed or stale polls. `syslog.event` counts matching messages in a bounded
  window. None of these actions can change the target host.
- HTTP, TCP, and TLS monitors are controller-originated network probes. They do
  not use SSH, the helper, or a host assignment, so a standalone monitor works
  when the target host is offline or unreachable. The target is therefore a
  controller egress destination; allowlist it in outbound firewall policy. HTTP
  targets reject embedded credentials, redirects are capped, and only status,
  latency, certificate expiry, and bounded error text are stored.
- An HTTP monitor can opt into `insecure_skip_verify`. This disables TLS
  certificate chain and hostname verification for that monitor only; encryption
  is still used. Use it only for trusted internal endpoints with self-signed or
  name-mismatched certificates. It is an authenticated admin setting and is
  shown as an **insecure TLS** badge in the monitor table.
- Optional single-hop `ProxyJump` uses a separately trusted jump-host key;
  HIBP verifies both the jump host and target host keys before running a helper
  action. Jump credentials are never logged, agent forwarding is not used, and
  multi-hop chains are rejected rather than flattened.
- Docker updates are project-level Compose operations. Project names and paths
  come from Docker metadata, not arbitrary controller input. The helper accepts
  exactly one validated project argument for check/apply, and a separate
  argument-free `docker-update-all` action for the bulk path. The `docker-check *`
  and `docker-apply *` sudoers wildcards are constrained by that validation.
  **Check all projects** and **Update selected** are controller-side loops over
  the same fixed per-project actions; they add no new privileged operation.
- Manual patch runs start with the read-only `preview` helper action. The
  controller shows upgrades, installs, and removals, then re-runs the preview
  immediately before apply and rejects the run if the package transaction hash
  changed. Removals require a typed `APPLY` confirmation in the UI and the
  `allow_removals` flag in the request. The preview and raw package-manager
  output may contain repository or package metadata; treat it as operational
  data and do not paste it into public issues.
- Per-project Docker status is stored in `docker_project_checks` inside the
  encrypted database. It contains project names, status, timestamps, and a
  bounded summary or helper error, never Compose file contents or secrets.
- Compose files and their parent directory chain must be root-owned and not
  group/world-writable. `.env` files and build contexts must be protected by the
  operator. No automatic updates, no `down -v`, and no volume pruning. Check,
  apply, and bulk update are serialised with a host-wide lock and audited.
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
  `preview`/`check`/`apply` helper actions as manual patching, use the configured cron
  timezone and maintenance window, and only target hosts with key auth and a
  trusted host key. Concurrency is bounded per schedule, only transient
  transport failures are retried (not authentication, host-key, sudo-policy, or
  package-manager failures), and every host attempt is written to run history
  and the audit log. Catch-up scans are bounded to the most recent 7 days, and
  jitter is re-checked against the maintenance window before starting. A
  schedule can opt in to a reboot after a
  successful apply when the fixed `reboot-check` reports it is required; the
  default is no reboot and there is no post-reboot verification. Treat that
  policy as destructive: use a canary assignment and low concurrency first. The
  target must run a helper and sudoers rule that support `reboot-check` and
  `reboot`. The
  scheduler is not a durable job queue: an interrupted run is not resumed, and
  the process must be unlocked and running. Manual patch, reboot, helper
  bootstrap, Docker check/apply, and scheduled patch operations share a
  process-local per-host lock; a second operation on the same host is rejected
  or skipped. Multiple controller processes must not share one database.
- SMTP is also used for schedule summaries. A local Postfix relay with no
  authentication is supported over a reachable TCP socket, but must be
  restricted to trusted sources; plain SMTP has no transport encryption.
- Durable manual jobs are stored in the encrypted database and execute only on
  hosts with key authentication and a trusted host key. Most actions also
  require the restricted NOPASSWD helper; helper-setup jobs additionally require
  non-interactive sudo for the binary install and `visudo` steps. A job records
  the authenticated actor, per-host state, bounded output, and audit entries.
  Jobs are process-local to one controller and must not be shared by running
  two controller processes against one database.
- Package deployment is root-equivalent. The controller stages one uploaded
  package under the database directory, transfers it over SSH, verifies the
  SHA-256, and invokes a fixed `install-package` helper action. The helper
  validates the package extension and header, creates a root-owned temporary
  file, and passes fixed argv to the target package manager. Installer
  environment names are validated and dangerous names such as `PATH`,
  `LD_PRELOAD`, and `SUDO_*` are rejected. RPM installs use DNF local-package
  GPG checking where available; Debian local `.deb` signature verification is
  not provided by `dpkg`, and pacman/apk follow the target's configured trust
  policy. HIBP does not replace the target's package signature policy; uploaded
  packages must be obtained from a trusted source.
- The staged package file is not encrypted at rest while the job is active.
  Keep the database directory on encrypted local storage, restrict the service
  account, and dismiss failed jobs when the package is no longer needed.
- CMDB import is read-only and file-based. HIBP never opens the CMDB database and
  never writes back. Imports are bounded (10 MiB, 5,000 records), validated, and
  previewed before commit. Imported data cannot contain HIBP secrets, and host
  keys are still approved only after an independent fingerprint check.
- SMTP credentials are stored only in the SQLCipher database and are never
  returned by the API, logged, or written to audit details. Use TLS for SMTP.
  Package installer environment values are also stored only in the encrypted
  job record and are never returned by the API.

## Public demo image

`hibp-demo` is a separate image built with the `demo` Go build tag. It is not the
production controller and must not be used to manage real hosts.

- The demo seeds a public `guest` account and exposes the demo password and TOTP
  secret on the sign-in page. TOTP replay protection is intentionally bypassed
  in demo mode so multiple visitors can use the displayed code.
- Every SSH connection, helper action, package installation, SMTP send, and
  HTTP/TCP/TLS monitor probe is simulated. Backup and restore return simulated
  success without writing arbitrary paths.
- The database is ephemeral and shared by all visitors. Restart the container to
  reset it. There is no per-visitor isolation.
- Account security changes and passkeys are disabled. The demo does not contain
  real credentials, SSH keys, SMTP credentials, or host keys.
- Run the demo non-root, with resource limits, a read-only root filesystem, a
  writable `/tmp` tmpfs, no Docker socket, no host mounts, and a TLS-terminating
  reverse proxy. Do not expose the demo HTTP listener directly to the internet.
- Demo responses set `X-Robots-Tag: noindex, nofollow` and `/robots.txt` denies
  indexing.

See [Public demo container](docs/demo.md) for deployment details.

## Operational guidance

- Use a unique database passphrase and full-disk encryption. For LAN HTTPS,
  use a certificate trusted by the clients and restrict the listener to the LAN
  subnet with a firewall.
- Complete first-run account and MFA setup immediately; until then anyone who
  can reach the loopback or LAN HTTPS UI could claim the administrator account.
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
- Package cleanup is destructive. HIBP never runs `apt autoremove`, `dnf
  autoremove`, zypper cleanup, or pacman orphan removal as part of a patch run.
  The fixed `cleanup-check`/`cleanup-apply` actions compute the orphan list on
  the target; the controller never supplies package names. The UI shows a
  dry-run list and requires typing `CLEAN`. The controller is excluded from bulk
  cleanup, and the server refuses a controller cleanup from a batch/API request
  unless the single-host action explicitly approves it. Alpine is unsupported.
  Review the list on a canary first; cleanup can remove a package someone still
  expects.
- Package cleanup uses fixed `cleanup-check` and `cleanup-apply` actions. The
  controller never supplies package names: the helper computes the orphan list
  on the target, returns it for review, and removes only that computed list.
  The UI requires a typed `CLEAN` confirmation, bulk cleanup excludes the
  controller, and unsupported package managers are reported instead of guessed.
  Cleanup is not part of patching and is not scheduled automatically.
- The `install-package` helper action is root-equivalent package installation.
  It accepts only a JSON request on stdin with a validated package filename,
  SHA-256, package bytes, and an installer environment allowlist, but the
  package's maintainer scripts still execute as root. Keep the helper and
  sudoers rule root-owned, restrict the SSH account, and deploy only packages
  from a trusted source. Do not treat this action as a low-risk file copy.
- The Checkmk registration runbook invokes a fixed `cmk-agent-ctl register`
  action as root and answers the certificate prompt with `y` on stdin. The
  registration password is kept only in controller memory for the active job,
  is never written to the persisted job payload, and is redacted from captured
  output. It is still passed to `cmk-agent-ctl` as an argv value, so it is
  briefly visible in the target process list. Use a dedicated Checkmk
  automation user, restrict who can log in to the target, and review the
  certificate details in the job output after registration. This action answers
  the prompt rather than using `--trust-cert`, which keeps certificate changes
  visible.
- The reboot action is destructive. Per-host and selected-host reboots require
  explicit confirmation in the API and UI, and selected-host reboots require
  typing `REBOOT`. The controller is detected from its hostname, short hostname,
  and local addresses and is excluded from bulk reboot. The server also refuses
  a controller reboot from a batch/API request unless the request explicitly
  carries per-host controller approval, which only the single-host UI action
  sends. A manual patch run or schedule can opt in to a reboot after a
  successful apply when the fixed `reboot-check` reports it is required; the
  default is no reboot, and automatic post-patch reboots refuse the controller.
  HIBP does not wait for or verify the rebooted host, so
  check kernel, boot ID, uptime, package state, and service health afterward.
- The local SSH config reader returns aliases, hostnames, users, ports, and key
  paths only. It never returns private key contents. Treat the config path and
  the imported metadata as sensitive.
- Remote helper installation uploads the controller binary to the target. Use
  the static release build, keep the host key pinned, and use the Setup flow
  only against hosts you intend to manage.
- Keep at least one encrypted backup off the controller and test restores.
- Treat the session cookie, the SSH tunnel or LAN HTTPS session, and the
  controller as credentials.
- Review any future approved playbooks before activation. Arbitrary shell is
  intentionally disabled in this release.
