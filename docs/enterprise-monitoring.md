# Enterprise monitoring design

Status: **implemented MVP.** Service-baseline drift, Docker-health defaults, NTP
sync/offset monitoring, severity-based email routing, journald/auth events with
a failed-authentication monitor, typed service/package/Checkmk runbooks, and the
cross-platform monitoring agent MVP are implemented. Custom log-file rules,
external agent adapters, mTLS/signed agent policy, and Windows performance/
Docker parity remain proposed.

## Goals

- Apply monitoring defaults fleet-wide to existing and new hosts.
- Detect failed or unexpectedly stopped services without creating one noisy
  monitor per unit.
- Detect NTP synchronization problems and material clock offset.
- Collect failed authentication events from server logs.
- Collect Docker health problems automatically.
- Allow fleet-wide default recipients with severity routing.
- Provide typed, configurable bulk actions for common operations.
- Expand the target-side collection path without turning HIBP into an
  unrestricted remote shell.
- Keep the controller's existing audit, confirmation, and least-privilege model.

## Confirmed decisions

These decisions came from the monitoring design review:

- Service monitoring uses **baseline drift**, not one monitor per running
  service. The first collection records the running-unit baseline; later checks
  alert when a baseline unit is failed, missing, or no longer running.
- Defaults apply to **existing and new hosts**, with a preview and opt-out.
- Defaults are **fleet settings** and can be overridden per host or group.
- NTP monitoring includes both synchronization state and clock offset.
- Failed-authentication monitoring is required.
- Docker container health monitoring is required automatically.
- Log collection starts with **structured journald** plus `/var/log/auth.log`
  and syslog where present. Custom log files/rules are a later, explicitly
  gated phase.
- Global email recipients are the default. Per-monitor overrides remain
  optional. Severity routing is required.
- Bulk operations use **typed runbooks** with validated parameters. Arbitrary
  shell is not a normal feature.
- First typed actions: restart service, remove package, enable/disable service.
  Package installation supports both the existing uploaded-package job and
  repository-name installs with validation and preview.
- The HIBP helper is the first collection path to expand. Existing Checkmk,
  Wazuh/Zabbix, or other agents are not replaced by this work. External agent
  adapters are also in scope, using a generic event-source interface rather
  than hard-coding vendor APIs into the core.
- A cross-platform HIBP agent is in scope for Linux (Ubuntu, Kali, Fedora) and
  Windows (Windows 11, Windows Server 2025). Windows is monitoring-only in this
  workstream. The server remains Linux-only.

## Current baseline

- `hibp server` is agentless over SSH. The target-side `hibp-helper` is a
  stateless root-owned binary invoked through a restricted sudoers rule.
- There is no persistent HIBP agent, mTLS enrollment, heartbeat, local buffer,
  or signed policy distribution.
- The collector polls `metrics` and `facts` over SSH.
- `metrics` already stores running and failed systemd units in
  `host_services`.
- `facts` stores only a boolean `time_sync_ok`.
- Monitoring supports CPU, memory, disk, load, Docker project/container,
  a single systemd unit, HTTP, TCP, and TLS.
- SMTP settings already provide global default recipients. Per-monitor and
  per-schedule recipients override them.
- Durable jobs use fixed job kinds and fixed helper actions.
- Arbitrary remote shell is explicitly outside the current security model.

Implemented in the current tree:

- `host_service_baseline` stores the per-host running-unit baseline.
- The collector records that baseline after the first successful metrics
  collection and, by default, adds units observed running later.
- `service.baseline` is a fleet-assigned default monitor for failed units and
  baseline drift. Per-host settings can disable it, disable automatic expansion,
  or exclude individual units; reset preserves exclusions.
- `docker.health` is a fleet-assigned default monitor for unhealthy,
  restarting, or dead containers. A `docker.container` monitor with target `*`
  provides strict all-container monitoring, including stopped containers.
  Per-host settings can disable Docker monitoring without changing the fleet
  monitor.
- The Monitoring view shows per-host monitor detail inline and through a
  per-monitor **Details** view.
- Migration 016 creates both default monitors for existing and new databases.
- Migration 017 adds NTP source, offset, stratum, and last-sync fields plus the
  fleet-assigned default `host.ntp` monitor.
- Migration 018 adds `host_events` storage and the fleet-assigned default
  `security.auth` monitor.
- The helper `events` action collects bounded journald/auth events; the
  collector stores them with deduplication and retention.
- The Monitoring view includes a normalized security and service event table.
- SMTP settings include warning, critical, and recovery recipient routing.

## Target architecture

### Policy layer

Add fleet-level monitoring policy settings, resolved with the existing
host-over-fleet precedence:

- `monitoring.services.mode`: `baseline`, `failed`, or `explicit`
- `monitoring.services.exclude`: per-host/group unit exclusions
- `monitoring.ntp.warning_seconds` and `monitoring.ntp.critical_seconds`
- `monitoring.auth.window_minutes`, `monitoring.auth.threshold`
- `monitoring.docker.mode`: `all`, `unhealthy`, or `off`
- `monitoring.logs.enabled`
- default severity routing

Defaults apply to existing and new hosts. The UI must preview the change and
allow per-host/group opt-out before applying.

### Service baseline

Do not create one monitor per service. Store a per-host baseline of running
systemd units and evaluate it as one fleet-level monitor.

Proposed tables:

- `host_service_baseline`: `host_id`, `unit`, `state`, `first_seen`,
  `last_seen`, `expected`, `excluded`, `updated_at`

Evaluation:

- failed unit: critical
- baseline unit not running or missing: critical
- baseline unit restarted repeatedly: warning or critical after a threshold
- new unit: informational, not alerted by default
- excluded unit: never alerted

The UI shows the baseline, allows “accept current state”, “exclude”, and
“disable for this host/group”.

### NTP and clock

Collect more than the current boolean:

- synchronization state
- selected source and stratum where available
- offset, jitter, and last successful synchronization
- fallback to `timedatectl` if no supported NTP daemon is present

Add a `host.ntp` monitor. Defaults are fleet-configurable; initial
recommendation: unsynchronized critical, offset >1s warning, >5s critical.
The monitor must fail closed when no reliable clock source is available.

### Log and event pipeline

The helper/agent reads structured events rather than shipping raw logs by
default:

- journald JSON with a persisted cursor
- `/var/log/auth.log` or `/var/log/secure` where present
- syslog where present
- later: explicitly allowed custom log paths

Normalize each event to bounded fields:

- host, timestamp, source, unit/service, severity
- username and remote IP only when present
- event type and a short message
- deduplication key

Built-in rule packs:

- SSH and sudo authentication failures
- failed systemd units and restart loops
- NTP synchronization and clock-step messages
- kernel OOM and serious kernel errors
- Docker daemon and container failures
- HIBP UI login failures

Custom log rules are an advanced phase. They must use a root-owned allowlist,
regular files only, no symlinks, bounded read sizes, RE2-compatible matching,
redaction, rate limits, and configurable retention. Raw log lines must not be
exposed through the API by default.

### Docker

Add a fleet-level Docker health monitor over the existing cached inventory:

- unhealthy container: critical
- restarting container: critical
- exited/stopped container that was running in the baseline: critical
- optional per-container monitors remain available

Use the existing `docker_containers` inventory and avoid a new SSH connection
per container. The fleet `docker.health` monitor covers unhealthy, restarting,
and dead containers. A `docker.container` monitor with target `*` is the strict
all-container check: any stopped or exited container is critical. An automatic
stopped-container baseline for `docker.health` remains a future improvement.

### Notifications

Keep the existing SMTP global recipients as the default. Add explicit severity
routing:

- warning recipients
- critical recipients
- recovery recipients
- optional per-monitor override

Later phases can add generic webhook, Teams, Slack, ntfy, and on-call
escalation. Do not add provider-specific code to the core before the generic
routing model exists.

### Typed runbooks

Implement configurable typed actions, not free-form shell:

- restart service
- remove package, with package-manager dry-run preview
- enable/disable service
- install package from distribution repositories, with package-name
  validation and dry-run preview
- install an uploaded package: reuse the existing uploaded-package job
- register a Linux host with Checkmk: run `cmk-agent-ctl register` as root and
  answer the certificate prompt with a typed confirmation

Each action:

- accepts typed parameters, validated on the controller and again on the target
- passes parameters as JSON over stdin, not interpolated into a shell
- has a fixed helper action and a matching exact sudoers rule
- creates a durable job with per-host state, bounded output, and audit entries
- supports canary hosts, explicit confirmation, and optional approval
- refuses unsafe package names, unit names, or arguments
- keeps transient secrets such as the Checkmk registration password in
  controller memory only and redacts them from captured output

A future approved-playbook feature may add reviewed scripts, but it is separate
from typed runbooks and requires signature/version/approval controls.

### Agent strategy

The HIBP helper is expanded first for service baselines, NTP data, Docker
inventory, and structured event collection. This keeps the existing SSH and
sudo boundary.

A persistent `hibp agent` is a later option for DMZ/NAT, real-time event
delivery, local buffering, and large fleets. If added, it must use outbound
mTLS, per-agent certificates, rotation/revocation, signed policy, signed
updates, and a minimal local interface. It must not expose a general shell.

Existing Checkmk, Wazuh/Zabbix, or other agents are not duplicated. They remain
in place, and HIBP can consume their normalized events through adapters or a
generic event-ingestion interface. The first adapter target must still be chosen
with the exact product, version, URL, and authentication model. HIBP helper
collection remains authoritative for service baseline, NTP, Docker inventory,
and typed runbooks until an adapter proves equivalent coverage and audit
semantics.

### HIBP agent and Windows scope

The HIBP agent is a separate cross-platform binary, not the Linux-only server
binary and not the stateless helper. The server remains Linux-only.

Planned platforms:

- Linux: Ubuntu, Kali, Fedora
- Windows: Windows 11 and Windows Server 2025, monitoring only

Planned behavior:

- outbound push from the agent to the HIBP LAN HTTPS endpoint
- systemd service on Linux; Windows service under LocalSystem
- root on Linux and LocalSystem on Windows are permitted
- heartbeat, version, capability reporting, local buffer, and retry
- Linux collectors: systemd services, journald/auth events, NTP, Docker
- Windows collectors: service state, Event Log, W32Time status, performance
  counters, and Docker where installed
- no arbitrary shell and no remote-control plane
- typed runbooks remain on the HIBP helper/SSH path; Windows runbooks and
  Windows Update patching are not part of this monitoring workstream

Implemented in the current tree:

- `hibp-agent` Linux and Windows binaries built by `make agent-build`
- agent token creation, rotation, and revocation per host
- `POST /api/v1/agent/v1/heartbeat`
- `POST /api/v1/agent/v1/snapshot`
- `POST /api/v1/agent/v1/events`
- token authentication via `Authorization: Bearer`
- Linux collection through the existing helper actions
- Windows service state, W32Time status, and Security/System Event Log events
- host `auth_type=agent`, which disables SSH-only actions

Still pending:

- mTLS, signed policy, signed agent updates, and certificate rotation
- external Checkmk/Wazuh/Zabbix adapters
- performance-counter and Windows Docker inventory parity
- agent installer/MSI packaging and service hardening

Security default:

- a per-agent shared token is used by default, even on an internal network
- an explicit `agent.auth=none` mode may exist for isolated lab use, but it is
  not the default
- agent endpoints should be restricted to loopback or a dedicated private
  interface and firewall allowlist
- TLS is required outside loopback; internal-only HTTP is a documented
  exception, not the preferred deployment

Agent-only hosts are represented as host records with an agent authentication
mode so monitoring assignments continue to use the existing fleet/group/tag/host
model. SSH-specific actions are disabled for agent-only hosts.

### Agent deployment

Build both binaries:

```bash
make agent-build
```

Linux example:

```bash
sudo ./dist/hibp-agent \
  --server https://hibp.lan:8443 \
  --token '<one-time-token>' \
  --interval 5m
```

Windows service example, run from an elevated prompt:

```powershell
sc.exe create HIBPAgent binPath= "C:\Program Files\HIBP\hibp-agent.exe --server https://hibp.lan:8443 --token <one-time-token> --interval 5m" start= auto
sc.exe start HIBPAgent
```

Create or rotate the token from the host row **Agent token** action. The token
is shown once. Use HTTPS for anything beyond a loopback or isolated lab
network. `--insecure-skip-verify` is a lab-only escape hatch.

## Data model changes

Migration `016_enterprise_monitoring.sql` is implemented and adds
`host_service_baseline` plus the default service-baseline and Docker-health
monitors. Migration `017_ntp_monitoring.sql` adds NTP telemetry fields and the
default `host.ntp` monitor. Migration `018_host_events.sql` adds `host_events`
and the default `security.auth` monitor. Later migrations start at `019_*.sql`:

- `host_events` normalized event records with retention fields
- `log_rules` built-in and custom rules
- `notification_routes` or settings-backed severity routing
- `runbook_actions`/job metadata as needed
- agent tables only if the persistent agent is approved

All tables must be forward-only, checksummed, tested against a previous-version
fixture, and include retention/index decisions.

## Security controls

- No arbitrary shell in the normal monitoring or runbook path.
- Typed parameters only; no shell interpolation.
- Exact helper actions and exact sudoers entries.
- Event collection is bounded, redacted, and rate-limited.
- Custom log paths require an explicit root-owned allowlist and reject symlinks,
  devices, directories, and oversized reads.
- Authentication events contain usernames and IPs; define retention and access
  policy before enabling them.
- Fleet policy changes are audited.
- Existing host-key verification, MFA, Host/Origin checks, and audit-chain rules
  remain unchanged.

## Phased delivery

### Phase 1 - Fleet monitoring defaults

- **Implemented:** service baseline and failed-unit evaluation.
- **Implemented:** per-host baseline settings, unit exclusions, automatic
  expansion of newly running units, and baseline reset.
- **Implemented:** Docker health default for unhealthy, restarting, and dead
  containers.
- **Implemented:** strict all-container monitoring with `docker.container`
  target `*`.
- **Implemented:** default monitors created by migration for existing and new
  databases.
- **Implemented:** NTP synchronization, source, stratum, and offset checks with
  a fleet-assigned default monitor.
- **Implemented:** global email default plus warning, critical, and recovery
  recipient routing. Per-monitor recipients still override the global policy.
- Pending: richer fleet-policy preview/opt-out beyond the per-host Service
  baseline controls.

### Phase 2 - Security and log events

- **Implemented:** journald auth/service/NTP/OOM event collection.
- **Implemented:** normalized `host_events` storage, deduplication, retention,
  and the event table in the Monitoring view.
- **Implemented:** fleet-wide failed-authentication monitor.
- **Implemented:** HIBP UI login failure events are not yet persisted; only the
  existing rate limiter covers them.
- Pending: `/var/log/auth.log` and syslog fallback is present but journald is
  the primary path.
- Pending: custom log paths and rules remain gated.
- Pending: automatic stopped-container baseline for `docker.health`; the strict
  `docker.container` target `*` mode is implemented.

### Phase 3 - Typed runbooks

- **Implemented:** restart, enable, and disable systemd services.
- **Implemented:** preview/apply package removal.
- **Implemented:** preview/apply repository package installation.
- **Implemented:** Checkmk agent registration with a typed certificate
  confirmation, transient registration password, and redacted output.
- **Implemented:** existing uploaded-package installation remains available.
- **Implemented:** typed parameters, controller/target validation, JSON over
  stdin, durable jobs, audit entries, and optional shared sudo password for the
  job.
- Pending: approval/canary UX beyond explicit confirmation.
- Pending: Windows service/package runbooks.

### Phase 4 - Agent and external integrations

- **Implemented:** cross-platform `hibp-agent` binaries for Linux and Windows.
- **Implemented:** outbound push, heartbeat, token auth, snapshot, and event
  endpoints.
- **Implemented:** Linux helper-based collection and Windows service/W32Time/
  Event Log collection MVP.
- **Implemented:** host `auth_type=agent` with SSH-only actions disabled.
- Pending: mTLS, signed policy, signed agent updates, and certificate rotation.
- Pending: external Checkmk/Wazuh/Zabbix adapters.
- Pending: Windows performance counters, Docker inventory parity, and
  installer/MSI packaging.

## Open decisions

- Exact default thresholds for NTP, authentication failures, restart loops,
  and Docker health. Initial recommendations are documented above and remain
  fleet-configurable.
- Which existing agent adapter comes first: Checkmk, Wazuh, or Zabbix. The exact
  product version, API endpoint, authentication model, and event-type ownership
  are still required.
- Retention periods for normalized events and raw log references.
- Whether custom log rules are enabled per fleet, per host, or only by a
  root-owned target-side configuration file.
- Approval model for destructive runbooks: typed confirmation only, or a second
  approver.
- Whether a persistent HIBP agent is required in Phase 1 for any environment, or
  whether agentless SSH is sufficient until DMZ/NAT requirements are confirmed.
