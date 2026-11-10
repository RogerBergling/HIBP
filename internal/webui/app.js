'use strict';

const state = {
  token: sessionStorage.getItem('hibp_token') || '',
  hosts: [],
  audit: [],
  status: {},
  view: 'dashboard',
  passwords: new Map(),
  sudoPasswords: new Map(),
};

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function icon(name) {
  const icons = {
    server: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><rect x="4" y="4" width="16" height="7" rx="1.5" stroke="currentColor" stroke-width="1.8"/><rect x="4" y="14" width="16" height="7" rx="1.5" stroke="currentColor" stroke-width="1.8"/></svg>',
    pending: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 4v10m0 4h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/></svg>',
    reboot: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 3v10" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M7 8a7 7 0 1010 0" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    check: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M5 12l4 4L19 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    host: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><rect x="4" y="4" width="16" height="7" rx="1.5" stroke="currentColor" stroke-width="1.8"/><rect x="4" y="14" width="16" height="7" rx="1.5" stroke="currentColor" stroke-width="1.8"/></svg>',
  };
  const span = el('span');
  span.innerHTML = icons[name] || '';
  return span;
}

function showTokenScreen() {
  $('app').classList.add('hidden');
  $('token-screen').classList.remove('hidden');
  $('token-input').focus();
}

function showApp() {
  $('token-screen').classList.add('hidden');
  $('app').classList.remove('hidden');
}

function setView(view) {
  state.view = view;
  for (const section of ['dashboard', 'hosts', 'audit']) {
    $('view-' + section).classList.toggle('hidden', section !== view);
  }
  for (const button of document.querySelectorAll('.nav-item[data-view]')) {
    button.classList.toggle('active', button.dataset.view === view);
  }
  $('crumb-view').textContent = view === 'dashboard' ? 'Overview' : view === 'hosts' ? 'Hosts' : 'Audit log';
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', 'Bearer ' + state.token);
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...options, headers, cache: 'no-store' });
  const text = await response.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (response.status === 401) {
    state.token = '';
    sessionStorage.removeItem('hibp_token');
    showTokenScreen();
    throw new Error('UI token rejected');
  }
  if (!response.ok) {
    const error = new Error(data.error || ('HTTP ' + response.status));
    error.data = data;
    error.status = response.status;
    throw error;
  }
  return data;
}

async function loadAll() {
  try {
    const [status, hosts, audit] = await Promise.all([
      api('/api/v1/status'),
      api('/api/v1/hosts'),
      api('/api/v1/audit?limit=200'),
    ]);
    state.status = status;
    state.hosts = hosts.hosts || [];
    state.audit = audit.entries || [];
    renderAll();
    $('last-refresh').textContent = 'updated ' + new Date().toLocaleTimeString();
  } catch (error) {
    toast(error.message, 'error');
  }
}

function renderAll() {
  renderStatus();
  renderStats();
  renderHosts();
  renderAudit();
}

function renderStatus() {
  $('server-version').textContent = 'HIBP ' + (state.status.version || 'dev');
  $('server-hosts').textContent = (state.hosts.length) + ' hosts';
  $('server-time').textContent = state.status.time ? new Date(state.status.time).toLocaleTimeString() : '—';
  $('nav-host-count').textContent = String(state.hosts.length);
}

function renderStats() {
  const total = state.hosts.length;
  const pending = state.hosts.reduce((sum, host) => sum + ((host.facts && host.facts.pending_updates) || 0), 0);
  const reboot = state.hosts.filter((host) => host.facts && host.facts.reboot_required).length;
  const reachable = state.hosts.filter((host) => host.status === 'reachable').length;
  const cards = [
    { label: 'Hosts managed', value: total, unit: 'hosts', foot: reachable + ' reachable', cls: '', icon: 'server' },
    { label: 'Patches pending', value: pending, unit: 'updates', foot: state.hosts.filter((h) => h.facts && h.facts.pending_updates > 0).length + ' hosts need attention', cls: 'amber', icon: 'pending' },
    { label: 'Reboot required', value: reboot, unit: 'hosts', foot: reboot ? 'review before rebooting' : 'none pending', cls: 'red', icon: 'reboot' },
    { label: 'Facts collected', value: state.hosts.filter((h) => h.facts).length, unit: 'hosts', foot: 'last check timestamps below', cls: 'green', icon: 'check' },
  ];
  const container = $('stats');
  container.replaceChildren();
  for (const card of cards) {
    const box = el('div', 'stat');
    const top = el('div', 'stat-top');
    const iconBox = el('span', 'stat-icon ' + card.cls);
    iconBox.append(icon(card.icon));
    top.append(iconBox, el('span', '', card.label));
    box.append(top);
    const value = el('div', 'stat-value', card.value);
    value.append(el('small', '', card.unit));
    box.append(value);
    box.append(el('div', 'stat-foot', card.foot));
    container.append(box);
  }
  $('page-sub').replaceChildren();
  $('page-sub').append(
    document.createTextNode(total + ' hosts · '),
    el('b', '', pending + ' pending updates'),
    document.createTextNode(' · ' + reboot + ' reboot required')
  );
  $('hosts-sub').textContent = total + ' hosts';
  $('hosts-page-sub').textContent = total + ' managed hosts';
  $('empty-state').classList.toggle('hidden', total !== 0);
}

function renderHosts() {
  const rows = state.hosts.map(hostRow);
  $('hosts-body').replaceChildren(...rows);
  $('hosts-body-full').replaceChildren(...state.hosts.map(hostRow));
}

function hostRow(host) {
  const tr = el('tr');
  const facts = host.facts || {};

  const hostTd = el('td');
  const hostCell = el('div', 'host-cell');
  const hostIcon = el('div', 'host-ico');
  hostIcon.append(icon('host'));
  const hostText = el('div');
  hostText.append(el('div', 'host-name', host.name), el('div', 'host-ip', host.address + ':' + host.port));
  hostCell.append(hostIcon, hostText);
  hostTd.append(hostCell);

  const osTd = el('td');
  const os = el('div', 'os', facts.os_pretty_name || host.os_family || 'Unknown');
  os.append(el('small', '', facts.kernel || (host.auth_type + ' auth')));
  osTd.append(os);

  const pending = Number(facts.pending_updates || 0);
  const pendingTd = el('td');
  const pendingEl = el('span', 'pending ' + (pending === 0 ? 'zero' : pending >= 5 ? 'high' : 'low'));
  pendingEl.append(el('span', 'count', pending), document.createTextNode(' updates'));
  pendingTd.append(pendingEl);

  const checkTd = el('td');
  checkTd.append(el('span', 'nowrap', relativeTime(facts.collected_at)));
  if (facts.collected_at) checkTd.append(el('div', 'muted', new Date(facts.collected_at).toLocaleString()));

  const uptimeTd = el('td');
  uptimeTd.append(el('span', 'nowrap', formatUptime(facts.uptime_seconds)));

  const rebootTd = el('td');
  rebootTd.append(el('span', facts.reboot_required ? 'reboot-yes' : 'reboot-no', facts.reboot_required ? 'Yes' : 'No'));

  const statusTd = el('td');
  const statusClass = host.status === 'reachable' ? 'reachable' : host.status === 'unreachable' ? 'unreachable' : 'unknown';
  statusTd.append(el('span', 'pill ' + statusClass, '● ' + (host.status || 'unknown')));

  const actionsTd = el('td');
  const actions = el('div', 'actions');
  actions.append(actionButton('Edit', () => showAddHostModal(host)));
  actions.append(actionButton('Test', () => testHost(host)));
  actions.append(actionButton('Facts', () => collectFacts(host)));
  actions.append(actionButton('Patch', () => showPatchModal(host)));
  actionsTd.append(actions);

  tr.append(hostTd, osTd, pendingTd, checkTd, uptimeTd, rebootTd, statusTd, actionsTd);
  return tr;
}

function actionButton(label, handler, cls = '') {
  const button = el('button', 'btn small ' + cls, label);
  button.type = 'button';
  button.addEventListener('click', handler);
  return button;
}

function renderAudit() {
  const mini = $('audit-mini');
  mini.replaceChildren();
  if (!state.audit.length) {
    mini.append(el('div', 'next-step', 'No audit entries yet.'));
  }
  for (const entry of state.audit.slice(0, 5)) {
    const item = el('div', 'audit-item');
    item.append(el('span', 'audit-dot'));
    const text = el('div');
    const line = el('div', 'audit-text');
    line.append(el('b', '', entry.action), document.createTextNode(' · ' + (entry.detail || entry.entity_type)));
    text.append(line, el('div', 'audit-time', relativeTime(entry.ts) + ' · ' + entry.actor));
    item.append(text);
    mini.append(item);
  }

  const body = $('audit-body');
  body.replaceChildren();
  for (const entry of state.audit) {
    const tr = el('tr');
    tr.append(
      el('td', '', String(entry.id)),
      el('td', '', new Date(entry.ts).toLocaleString()),
      el('td', '', entry.actor),
      el('td', '', entry.action),
      el('td', '', entry.entity_type + (entry.entity_id ? ' · ' + entry.entity_id.slice(0, 8) : '')),
      el('td', '', entry.detail || '')
    );
    body.append(tr);
  }
}

function relativeTime(value) {
  if (!value) return '—';
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) return '—';
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
  if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
  return Math.floor(seconds / 86400) + 'd ago';
}

function formatUptime(seconds) {
  if (!seconds) return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return days + 'd';
  return hours + 'h';
}

function passwordFor(host) {
  if (host.auth_type !== 'password') return '';
  if (state.passwords.has(host.id)) return state.passwords.get(host.id);
  const value = prompt('SSH password for ' + host.name + ' (not stored):');
  if (value === null) throw new Error('cancelled');
  state.passwords.set(host.id, value);
  return value;
}

function sudoPasswordFor(host) {
  if (state.sudoPasswords.has(host.id)) return state.sudoPasswords.get(host.id);
  const value = prompt('sudo password for ' + host.name + ' (not stored; used for this session):');
  if (value === null) throw new Error('cancelled');
  state.sudoPasswords.set(host.id, value);
  return value;
}

async function requestWithSudo(host, path, payloadFor, options = {}) {
  const request = (sudoPassword) => api(path, {
    ...options,
    body: JSON.stringify(payloadFor(sudoPassword)),
  });
  try {
    return await request('');
  } catch (error) {
    if (error.status === 409 && error.data && error.data.code === 'sudo_password_required') {
      return request(sudoPasswordFor(host));
    }
    if (error.status === 400 && error.data && error.data.code === 'sudo_password_invalid') {
      state.sudoPasswords.delete(host.id);
    }
    throw error;
  }
}

async function testHost(host) {
  try {
    const password = passwordFor(host);
    await api('/api/v1/hosts/' + encodeURIComponent(host.id) + '/test', { method: 'POST', body: JSON.stringify({ password }) });
    toast('Connection and host key verified for ' + host.name, 'ok');
    await loadAll();
  } catch (error) {
    if (error.status === 409 && error.data && error.data.key) {
      showTrustModal(host, error.data.key, state.passwords.get(host.id) || '');
      return;
    }
    toast(error.message, 'error');
  }
}

function showTrustModal(host, key, password) {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Verify this fingerprint through an independent channel before trusting it.'));
  const box = el('div', 'key-box', key.key_type + ' ' + key.fingerprint);
  body.append(box);
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const trust = el('button', 'btn primary', 'Trust this key');
  trust.type = 'button';
  actions.append(cancel, trust);
  body.append(actions);
  const close = openModal('Unknown host key — ' + host.name, body);
  cancel.addEventListener('click', close);
  trust.addEventListener('click', async () => {
    try {
      await api('/api/v1/hosts/' + encodeURIComponent(host.id) + '/trust-key', {
        method: 'POST',
        body: JSON.stringify({ key_type: key.key_type, fingerprint: key.fingerprint, password }),
      });
      close();
      toast('Host key trusted. Testing connection…', 'ok');
      await testHost(host);
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

async function collectFacts(host) {
  toast('Collecting facts from ' + host.name + '…');
  try {
    const password = passwordFor(host);
    await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/facts',
      (sudoPassword) => ({ password, sudo_password: sudoPassword }),
      { method: 'POST' },
    );
    toast('Facts collected from ' + host.name, 'ok');
    await loadAll();
  } catch (error) {
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

function showPatchModal(host) {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Dry-run shows what would change. Apply runs the root-owned helper on the target.'));
  const facts = host.facts || {};
  const summary = el('div', 'status-list');
  const row = (label, value) => {
    const div = el('div');
    div.append(el('span', '', label), el('b', '', value));
    return div;
  };
  summary.append(
    row('Host', host.name),
    row('Pending updates', String(facts.pending_updates || 0)),
    row('Reboot required', facts.reboot_required ? 'yes' : 'no')
  );
  body.append(summary);
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const dry = el('button', 'btn', 'Dry run');
  dry.type = 'button';
  const apply = el('button', 'btn danger', 'Apply updates');
  apply.type = 'button';
  actions.append(cancel, dry, apply);
  body.append(actions);
  const close = openModal('Patch — ' + host.name, body);
  cancel.addEventListener('click', close);
  dry.addEventListener('click', () => { close(); patchHost(host, true); });
  apply.addEventListener('click', () => { close(); patchHost(host, false); });
}

async function patchHost(host, dryRun) {
  if (!dryRun && !confirm('Apply updates on ' + host.name + '? This runs the root-owned helper on the target.')) return;
  toast((dryRun ? 'Checking' : 'Applying updates on') + ' ' + host.name + '…');
  try {
    const password = passwordFor(host);
    const result = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/patch',
      (sudoPassword) => ({ dry_run: dryRun, confirm: dryRun ? '' : 'apply', password, sudo_password: sudoPassword }),
      { method: 'POST' },
    );
    showOutputModal((dryRun ? 'Patch check' : 'Patch run') + ' — ' + host.name, result);
    await loadAll();
  } catch (error) {
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

function showOutputModal(title, result) {
  const body = el('div', 'modal-body');
  const meta = el('div', 'status-list');
  const row = (label, value) => {
    const div = el('div');
    div.append(el('span', '', label), el('b', result.ok ? 'ok' : '', value));
    return div;
  };
  meta.append(row('Action', result.action || '—'), row('Exit code', String(result.exit_code ?? '—')));
  body.append(meta);
  const pre = el('pre', 'key-box', result.output || result.error || 'No output');
  pre.style.whiteSpace = 'pre-wrap';
  pre.style.maxHeight = '320px';
  pre.style.overflow = 'auto';
  body.append(pre);
  const actions = el('div', 'modal-actions');
  const close = el('button', 'btn', 'Close');
  close.type = 'button';
  actions.append(close);
  body.append(actions);
  const closeFn = openModal(title, body);
  close.addEventListener('click', closeFn);
}

function openModal(title, content) {
  const root = $('modal-root');
  root.replaceChildren();
  const backdrop = el('div', 'modal-backdrop');
  const modal = el('div', 'modal');
  const head = el('div', 'modal-head');
  const close = el('button', 'modal-close', '×');
  close.type = 'button';
  head.append(el('div', 'modal-title', title), close);
  modal.append(head, content);
  backdrop.append(modal);
  root.append(backdrop);
  const closeFn = () => root.replaceChildren();
  close.addEventListener('click', closeFn);
  backdrop.addEventListener('click', (event) => { if (event.target === backdrop) closeFn(); });
  const onKey = (event) => { if (event.key === 'Escape') { closeFn(); document.removeEventListener('keydown', onKey); } };
  document.addEventListener('keydown', onKey);
  return closeFn;
}

function showAddHostModal(host = null) {
  const editing = Boolean(host);
  const form = el('form', 'modal-body');
  const name = inputField(form, 'Name', 'name', 'web01');
  const address = inputField(form, 'Address', 'address', '10.0.0.10');
  const row = el('div', 'form-row');
  const port = inputField(row, 'Port', 'port', '22', 'number');
  const username = inputField(row, 'Username', 'username', 'ubuntu');
  form.append(row);
  const authRow = el('div', 'form-row');
  const authType = selectField(authRow, 'Auth type', 'auth_type', [['key', 'SSH key'], ['agent', 'ssh-agent'], ['certificate', 'SSH certificate'], ['password', 'Password (manual fallback)']]);
  const keyPath = keyPathField(authRow, host?.key_path || '');
  form.append(authRow);
  const groupRow = el('div', 'form-row');
  const group = inputField(groupRow, 'Group', 'group_name', 'web-prod');
  const tags = inputField(groupRow, 'Tags', 'tags', 'web,prod');
  form.append(groupRow);
  const cmdb = inputField(form, 'CMDB CI ID', 'cmdb_ci_id', 'CI-123');

  name.value = host?.name || '';
  address.value = host?.address || '';
  port.value = String(host?.port || 22);
  username.value = host?.username || '';
  authType.value = host?.auth_type || 'key';
  group.value = host?.group_name || '';
  tags.value = host?.tags || '';
  cmdb.value = host?.cmdb_ci_id || '';

  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const save = el('button', 'btn primary', editing ? 'Save changes' : 'Add host');
  save.type = 'submit';
  actions.append(cancel, save);
  form.append(actions);
  const close = openModal(editing ? 'Edit host — ' + host.name : 'Add host', form);
  cancel.addEventListener('click', close);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {
      name: name.value.trim(), address: address.value.trim(), port: Number(port.value || 22),
      username: username.value.trim(), auth_type: authType.value, key_path: keyPath.value.trim(),
      group_name: group.value.trim(), tags: tags.value.trim(), cmdb_ci_id: cmdb.value.trim(),
    };
    try {
      const url = editing ? '/api/v1/hosts/' + encodeURIComponent(host.id) : '/api/v1/hosts';
      const method = editing ? 'PUT' : 'POST';
      await api(url, { method, body: JSON.stringify(payload) });
      close();
      toast(editing ? 'Host updated' : 'Host added', 'ok');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

function keyPathField(parent, value) {
  const wrapper = el('label', 'field', 'Key path');
  const row = el('div', 'input-with-button');
  const input = el('input');
  input.name = 'key_path';
  input.type = 'text';
  input.placeholder = '/home/ops/.ssh/id_ed25519';
  input.autocomplete = 'off';
  input.spellcheck = false;
  input.value = value || '';
  const browse = el('button', 'btn small', 'Browse');
  browse.type = 'button';
  browse.addEventListener('click', () => showKeyBrowser((selected) => { input.value = selected; }));
  row.append(input, browse);
  wrapper.append(row);
  parent.append(wrapper);
  return input;
}

async function showKeyBrowser(onSelect) {
  const body = el('div', 'modal-body');
  const pathBox = el('div', 'key-box', 'Loading…');
  const rootsBox = el('div', 'file-roots');
  const list = el('div', 'file-list');
  body.append(pathBox, rootsBox, list);
  const actions = el('div', 'modal-actions');
  const up = el('button', 'btn small', 'Up');
  up.type = 'button';
  const refresh = el('button', 'btn small', 'Refresh');
  refresh.type = 'button';
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  actions.append(up, refresh, cancel);
  body.append(actions);
  const close = openModal('Choose SSH key file', body);
  let current = '';

  const load = async (path) => {
    try {
      const data = await api('/api/v1/keys?path=' + encodeURIComponent(path || ''));
      current = data.path;
      pathBox.textContent = current;
      rootsBox.replaceChildren();
      up.disabled = (data.roots || []).includes(current);
      for (const root of data.roots || []) {
        const rootButton = el('button', 'btn small', root);
        rootButton.type = 'button';
        rootButton.addEventListener('click', () => load(root));
        rootsBox.append(rootButton);
      }
      list.replaceChildren();
      if (!data.entries || data.entries.length === 0) {
        list.append(el('div', 'next-step', 'This directory is empty.'));
      }
      for (const entry of data.entries || []) {
        const row = el('div', 'file-row');
        const button = el('button', 'file-name', (entry.is_dir ? '📁 ' : '🔑 ') + entry.name + (entry.is_dir ? '/' : ''));
        button.type = 'button';
        button.addEventListener('click', () => {
          if (entry.is_dir) {
            load(entry.path);
          } else {
            onSelect(entry.path);
            close();
          }
        });
        row.append(button);
        row.append(el('span', 'file-meta', entry.is_dir ? 'directory' : entry.mode + ' · ' + formatBytes(entry.size)));
        if (!entry.is_dir) {
          const use = el('button', 'btn small', 'Use');
          use.type = 'button';
          use.addEventListener('click', () => { onSelect(entry.path); close(); });
          row.append(use);
        }
        list.append(row);
      }
    } catch (error) {
      list.replaceChildren();
      list.append(el('div', 'next-step', error.message));
    }
  };
  up.addEventListener('click', () => {
    const parent = current.substring(0, current.lastIndexOf('/')) || '/';
    load(parent);
  });
  refresh.addEventListener('click', () => load(current));
  cancel.addEventListener('click', close);
  await load('');
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KiB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MiB';
}

function inputField(parent, label, name, placeholder, type = 'text') {
  const wrapper = el('label', 'field', label);
  const input = el('input');
  input.name = name;
  input.type = type;
  input.placeholder = placeholder || '';
  input.autocomplete = 'off';
  input.spellcheck = false;
  wrapper.append(input);
  parent.append(wrapper);
  return input;
}

function selectField(parent, label, name, options) {
  const wrapper = el('label', 'field', label);
  const select = el('select');
  select.name = name;
  for (const [value, text] of options) {
    const option = el('option', '', text);
    option.value = value;
    select.append(option);
  }
  wrapper.append(select);
  parent.append(wrapper);
  return select;
}

function showImportModal() {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'CSV headers: name,address,port,username,auth_type,key_path,group,tags,cmdb_ci_id. A preview is always shown before commit.'));
  const file = el('input');
  file.type = 'file';
  file.accept = '.csv,.txt,text/csv,text/plain';
  body.append(file);
  const textarea = el('textarea');
  textarea.placeholder = 'name,address,port,username,auth_type,key_path\nweb01,10.0.0.10,22,ubuntu,key,/home/ops/.ssh/id_ed25519';
  body.append(textarea);
  const policyWrap = el('label', 'field', 'Duplicate policy');
  const policy = el('select');
  for (const [value, text] of [['error', 'Error on duplicate'], ['skip', 'Skip duplicates'], ['update', 'Update duplicates']]) {
    const option = el('option', '', text);
    option.value = value;
    policy.append(option);
  }
  policyWrap.append(policy);
  body.append(policyWrap);
  const defaultKeyPath = inputField(body, 'Default key path (optional)', 'default_key_path', '/home/ops/.ssh/id_ed25519');
  const preview = el('div', 'import-preview hidden');
  body.append(preview);
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const previewButton = el('button', 'btn', 'Preview');
  previewButton.type = 'button';
  const commitButton = el('button', 'btn primary', 'Commit');
  commitButton.type = 'button';
  commitButton.disabled = true;
  actions.append(cancel, previewButton, commitButton);
  body.append(actions);
  const close = openModal('Import hosts from CSV', body);
  cancel.addEventListener('click', close);
  file.addEventListener('change', async () => {
    const selected = file.files && file.files[0];
    if (selected) textarea.value = await selected.text();
  });
  previewButton.addEventListener('click', async () => {
    try {
      const result = await api('/api/v1/import', { method: 'POST', body: JSON.stringify({ csv: textarea.value, commit: false, duplicate_policy: policy.value, default_key_path: defaultKeyPath.value.trim() }) });
      renderImportPreview(preview, result);
      preview.classList.remove('hidden');
      commitButton.disabled = !result.rows || result.rows.length === 0;
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  commitButton.addEventListener('click', async () => {
    try {
      const result = await api('/api/v1/import', { method: 'POST', body: JSON.stringify({ csv: textarea.value, commit: true, duplicate_policy: policy.value, default_key_path: defaultKeyPath.value.trim() }) });
      close();
      toast('Import complete: ' + result.imported + ' added, ' + result.updated + ' updated, ' + result.skipped + ' skipped', 'ok');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

function renderImportPreview(container, result) {
  container.replaceChildren();
  if (result.errors && result.errors.length) {
    const errors = el('div', 'next-step');
    errors.style.color = '#fca5a5';
    errors.textContent = result.errors.join('\n');
    container.append(errors);
  }
  const table = el('table');
  const head = el('tr');
  for (const label of ['Row', 'Name', 'Address', 'Port', 'User', 'Error']) head.append(el('th', '', label));
  table.append(head);
  for (const row of result.rows || []) {
    const tr = el('tr');
    tr.append(el('td', '', row.row), el('td', '', row.name), el('td', '', row.address), el('td', '', row.port), el('td', '', row.username), el('td', '', row.error || 'ok'));
    table.append(tr);
  }
  container.append(table);
}

function showBackupModal() {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Creates a consistent encrypted copy plus the .meta sidecar. The path must not exist.'));
  const path = inputField(body, 'Backup path', 'path', '/var/backups/hibp-2026-11-10.hibp');
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const backup = el('button', 'btn primary', 'Backup');
  backup.type = 'button';
  actions.append(cancel, backup);
  body.append(actions);
  const close = openModal('Backup database', body);
  cancel.addEventListener('click', close);
  backup.addEventListener('click', async () => {
    try {
      const result = await api('/api/v1/backup', { method: 'POST', body: JSON.stringify({ path: path.value.trim() }) });
      close();
      toast('Backup written: ' + result.path, 'ok');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

function showRestoreModal() {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Copies a backup pair to a new database path and verifies it. Restart the server with --db pointing at the restored file to use it.'));
  const backupPath = inputField(body, 'Backup path', 'backup_path', '/var/backups/hibp-2026-11-10.hibp');
  const destPath = inputField(body, 'New database path', 'dest_path', '/var/lib/hibp/restored.hibp');
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const restore = el('button', 'btn primary', 'Restore');
  restore.type = 'button';
  actions.append(cancel, restore);
  body.append(actions);
  const close = openModal('Restore backup', body);
  cancel.addEventListener('click', close);
  restore.addEventListener('click', async () => {
    try {
      const result = await api('/api/v1/restore', { method: 'POST', body: JSON.stringify({ backup_path: backupPath.value.trim(), dest_path: destPath.value.trim() }) });
      close();
      toast('Restored to ' + result.path + '. Restart the server with --db ' + result.path, 'ok');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

async function verifyAudit() {
  try {
    const result = await api('/api/v1/audit/verify');
    toast(result.ok ? 'Audit chain verified' : 'Audit chain failed', result.ok ? 'ok' : 'error');
  } catch (error) {
    toast(error.message, 'error');
  }
}

function toast(message, type = '') {
  const node = $('toast');
  node.textContent = message;
  node.className = 'toast ' + type;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.add('hidden'), 4500);
}

function bind() {
  $('token-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const token = $('token-input').value.trim();
    if (!token) return;
    state.token = token;
    sessionStorage.setItem('hibp_token', token);
    showApp();
    loadAll();
  });
  for (const button of document.querySelectorAll('.nav-item[data-view]')) {
    button.addEventListener('click', () => setView(button.dataset.view));
  }
  $('top-refresh').addEventListener('click', loadAll);
  $('refresh-button').addEventListener('click', loadAll);
  $('top-add-host').addEventListener('click', showAddHostModal);
  $('empty-add').addEventListener('click', showAddHostModal);
  $('import-button').addEventListener('click', showImportModal);
  $('table-import').addEventListener('click', showImportModal);
  $('hosts-import').addEventListener('click', showImportModal);
  $('backup-button').addEventListener('click', showBackupModal);
  $('restore-button').addEventListener('click', showRestoreModal);
  $('verify-audit').addEventListener('click', verifyAudit);
  $('audit-verify').addEventListener('click', verifyAudit);
}

async function init() {
  bind();
  const params = new URLSearchParams(location.search);
  const urlToken = params.get('token');
  if (urlToken) {
    state.token = urlToken;
    sessionStorage.setItem('hibp_token', urlToken);
    params.delete('token');
    const query = params.toString();
    history.replaceState({}, '', location.pathname + (query ? '?' + query : ''));
  }
  if (!state.token) {
    showTokenScreen();
    return;
  }
  showApp();
  await loadAll();
}

init();
