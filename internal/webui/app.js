'use strict';

const state = {
  hosts: [],
  selectedHosts: new Set(),
  selectedMonitors: new Set(),
  monitorSort: { key: 'name', dir: 'asc' },
  monitorMapGroup: 'status',
  audit: [],
  monitors: [],
  alerts: [],
  events: [],
  jobs: [],
  jobDetail: null,
  schedules: [],
  runs: [],
  status: {},
  view: 'dashboard',
  passwords: new Map(),
  sudoPasswords: new Map(),
  sharedSudoPassword: '',
  sharedSudoUsername: '',
  auth: { user: null, setupRequired: false, authenticated: false, mfaRequired: false, enrollmentRequired: false, webauthnAvailable: false },
  demo: null,
  totpSetup: null,
};

const operationState = {
  active: false,
  title: '',
  detail: '',
  startedAt: 0,
  progress: 0,
  total: 0,
  finishedAt: 0,
  finishedTitle: '',
  finishedDetail: '',
  error: false,
};

const autoRefreshState = {
  enabled: true,
  timer: null,
  loading: false,
};

const jobDockState = {
  open: false,
  expanded: true,
  loading: false,
  timer: null,
};

let jobPollTimer = null;
let jobPollingStopped = false;
let demoCodeTimer = null;
let demoLoginBusy = false;

const demoSessionKey = 'hibp-demo-session';
const demoSessionHeader = 'X-HIBP-Demo-Session';

function getDemoSession() {
  try {
    return window.sessionStorage.getItem(demoSessionKey) || '';
  } catch (error) {
    return '';
  }
}

function setDemoSession(token) {
  try {
    if (token) {
      window.sessionStorage.setItem(demoSessionKey, token);
    } else {
      window.sessionStorage.removeItem(demoSessionKey);
    }
  } catch (error) {
    // Session storage can be disabled; the cookie remains the fallback.
  }
}

function withDemoSession(headers) {
  const token = getDemoSession();
  if (token) headers.set(demoSessionHeader, token);
  return headers;
}

try {
  autoRefreshState.enabled = window.localStorage.getItem('hibp-live-refresh') !== 'off';
} catch (error) {}

function beginOperation(title, detail = '', total = 0) {
  operationState.active = true;
  operationState.title = title;
  operationState.detail = detail;
  operationState.startedAt = Date.now();
  operationState.progress = 0;
  operationState.total = total;
  operationState.finishedAt = 0;
  operationState.error = false;
  renderOperationBar();
}

function updateOperation(detail, progress = null, total = null) {
  if (!operationState.active) return;
  if (detail !== null && detail !== undefined) operationState.detail = detail;
  if (progress !== null && progress !== undefined) operationState.progress = progress;
  if (total !== null && total !== undefined) operationState.total = total;
  renderOperationBar();
}

function finishOperation(title, detail = '', error = false) {
  operationState.active = false;
  operationState.finishedAt = Date.now();
  operationState.finishedTitle = title;
  operationState.finishedDetail = detail;
  operationState.error = error;
  renderOperationBar();
}

function operationElapsed(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) seconds = 0;
  if (seconds < 60) return seconds + 's';
  return Math.floor(seconds / 60) + 'm ' + String(seconds % 60).padStart(2, '0') + 's';
}

function renderOperationBar() {
  const bar = $('operation-bar');
  if (!bar) return;
  let title = '';
  let detail = '';
  let elapsed = 0;
  let percent = null;
  let tone = '';
  let show = false;
  if (operationState.active) {
    show = true;
    title = operationState.title;
    detail = operationState.detail;
    elapsed = Math.floor((Date.now() - operationState.startedAt) / 1000);
    if (operationState.total > 0) {
      percent = Math.max(0, Math.min(100, Math.round((operationState.progress / operationState.total) * 100)));
    }
  } else if (operationState.finishedAt && Date.now() - operationState.finishedAt < 4500) {
    show = true;
    title = operationState.finishedTitle;
    detail = operationState.finishedDetail;
    elapsed = Math.max(0, Math.floor((operationState.finishedAt - operationState.startedAt) / 1000));
    tone = operationState.error ? 'error' : 'done';
    percent = 100;
  } else {
    const running = (state.runs || []).find((run) => run.status === 'running');
    if (running) {
      const host = (state.hosts || []).find((entry) => entry.id === running.host_id);
      const action = running.action === 'patch-apply' ? 'Patch apply' : running.action === 'patch-check' ? 'Patch check' : running.action;
      show = true;
      title = 'Scheduled ' + action.toLowerCase() + ' running' + (host ? ' — ' + host.name : '');
      detail = 'Started ' + (running.started_at ? new Date(running.started_at).toLocaleTimeString() : 'recently') + ' · live run history updates automatically';
      elapsed = running.started_at ? Math.max(0, Math.floor((Date.now() - new Date(running.started_at).getTime()) / 1000)) : 0;
    }
  }
  if (!show) {
    bar.classList.add('hidden');
    bar.classList.remove('done', 'error', 'indeterminate');
    return;
  }
  bar.classList.remove('hidden', 'done', 'error', 'indeterminate');
  if (tone) bar.classList.add(tone);
  if (percent === null) bar.classList.add('indeterminate');
  $('operation-title').textContent = title;
  $('operation-detail').textContent = detail || 'Working…';
  $('operation-elapsed').textContent = operationElapsed(elapsed);
  const fill = $('operation-fill');
  if (percent !== null) fill.style.width = percent + '%';
  else fill.style.width = '';
}

function setAutoRefresh(enabled) {
  autoRefreshState.enabled = Boolean(enabled);
  try {
    window.localStorage.setItem('hibp-live-refresh', autoRefreshState.enabled ? 'on' : 'off');
  } catch (error) {}
  const toggle = $('auto-refresh-toggle');
  if (toggle) toggle.checked = autoRefreshState.enabled;
  if (autoRefreshState.timer) {
    window.clearInterval(autoRefreshState.timer);
    autoRefreshState.timer = null;
  }
  if (autoRefreshState.enabled) {
    autoRefreshState.timer = window.setInterval(() => {
      if (document.visibilityState === 'visible' && !modalStack.length) {
        loadAll({ silent: true });
      }
    }, 15000);
  }
}

const modalStack = [];

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && modalStack.length) {
    event.preventDefault();
    modalStack[modalStack.length - 1].close();
  }
});

const $ = (id) => document.getElementById(id);

function versionLabel(version) {
  const value = String(version || '').trim();
  if (!value) return '';
  return value.startsWith('v') ? value : 'v' + value;
}

function buildIdentity(info) {
  if (!info) return '';
  const parts = [];
  if (info.version) parts.push(versionLabel(info.version));
  if (info.build_number) parts.push('build ' + info.build_number);
  if (info.build_commit) parts.push('commit ' + info.build_commit);
  if (info.build_date) parts.push(info.build_date);
  if (info.build_target) parts.push(info.build_target);
  if (info.build_type) parts.push(info.build_type);
  return parts.join(' · ');
}

function buildCompact(info) {
  if (!info) return '';
  const parts = [];
  if (info.version) parts.push(versionLabel(info.version));
  if (info.build_number) parts.push('build ' + info.build_number);
  if (info.build_commit) parts.push('commit ' + info.build_commit);
  return parts.join(' · ');
}

function selectedHosts() {
  return state.hosts.filter((host) => state.selectedHosts.has(host.id));
}

function controllerNameVariants(value) {
  const normalized = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!normalized) return [];
  const variants = [normalized];
  // Match a short inventory name to the controller FQDN (and vice versa), but
  // never split an IPv4 or IPv6 address into a bogus short name.
  const ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(normalized);
  if (!ipv4 && !normalized.includes(':')) {
    const dot = normalized.indexOf('.');
    if (dot > 0) variants.push(normalized.slice(0, dot));
  }
  return variants;
}

function controllerHostNames() {
  const controller = state.status.controller || {};
  const values = ['localhost', '127.0.0.1', '::1'];
  if (controller.hostname) values.push(controller.hostname);
  for (const address of controller.addresses || []) values.push(address);
  const names = new Set();
  for (const value of values) {
    for (const variant of controllerNameVariants(value)) names.add(variant);
  }
  return names;
}

function isControllerHost(host) {
  const names = controllerHostNames();
  return [host.name, host.address].some((value) =>
    controllerNameVariants(value).some((variant) => names.has(variant)));
}

function syncHostSelection() {
  const hostIDs = new Set(state.hosts.map((host) => host.id));
  for (const id of Array.from(state.selectedHosts)) {
    if (!hostIDs.has(id)) state.selectedHosts.delete(id);
  }
  for (const checkbox of document.querySelectorAll('.host-select')) {
    checkbox.checked = state.selectedHosts.has(checkbox.dataset.hostId);
  }
  const total = state.hosts.length;
  const count = state.selectedHosts.size;
  for (const id of ['hosts-select-all', 'hosts-select-all-full']) {
    const node = $(id);
    if (!node) continue;
    node.checked = total > 0 && count === total;
    node.indeterminate = count > 0 && count < total;
  }
  for (const id of ['table-update-selected', 'fleet-update-selected']) {
    const node = $(id);
    if (!node) continue;
    node.disabled = count === 0;
    node.textContent = count ? 'Setup selected (' + count + ')' : 'Setup selected';
  }
  for (const id of ['table-patch-selected', 'fleet-patch-selected']) {
    const node = $(id);
    if (!node) continue;
    node.disabled = count === 0;
    node.textContent = count ? 'Patch selected (' + count + ')' : 'Patch selected';
  }
  for (const id of ['table-cleanup-selected', 'fleet-cleanup-selected']) {
    const node = $(id);
    if (!node) continue;
    node.disabled = count === 0;
    node.textContent = count ? 'Clean up unused (' + count + ')' : 'Clean up unused';
  }
  for (const id of ['table-reboot-selected', 'fleet-reboot-selected']) {
    const node = $(id);
    if (!node) continue;
    node.disabled = count === 0;
    node.textContent = count ? 'Reboot selected (' + count + ')' : 'Reboot selected';
  }
  for (const id of ['table-facts-selected', 'fleet-facts-selected']) {
    const node = $(id);
    if (!node) continue;
    node.disabled = count === 0;
    node.textContent = count ? 'Collect facts (' + count + ')' : 'Collect facts';
  }
  for (const id of ['table-runbook-selected', 'fleet-runbook-selected']) {
    const node = $(id);
    if (!node) continue;
    node.disabled = count === 0;
    node.textContent = count ? 'Runbook (' + count + ')' : 'Runbook';
  }
}

function setAllHostSelection(checked) {
  state.selectedHosts.clear();
  if (checked) {
    for (const host of state.hosts) state.selectedHosts.add(host.id);
  }
  syncHostSelection();
}

function selectedMonitors() {
  return state.monitors.filter((monitor) => state.selectedMonitors.has(monitor.id));
}

function monitorScopeText(monitor) {
  const assignments = monitor.assignments || [];
  if (isNetworkMonitorType(monitor.type) || !assignments.length) return 'Standalone';
  return assignments.map((assignment) => monitorAssignmentLabel(assignment)).join(', ');
}

function monitorSortValue(monitor, key, aggregate) {
  switch (key) {
    case 'name': return String(monitor.name || '').toLowerCase() || null;
    case 'type': return monitorTypeLabel(monitor.type).toLowerCase() || null;
    case 'target': return String(monitor.target || '').toLowerCase() || null;
    case 'scope': return monitorScopeText(monitor).toLowerCase() || null;
    case 'interval': return Number(monitor.interval_seconds) || 0;
    case 'status': return MONITOR_STATUS_RANK[(aggregate || {}).status] ?? 0;
    case 'checked': {
      if (!monitor.last_checked_at) return null;
      const value = Date.parse(monitor.last_checked_at);
      return Number.isFinite(value) ? value : null;
    }
    default: return null;
  }
}

function sortedMonitors(monitors, aggregates) {
  const direction = state.monitorSort.dir === 'asc' ? 1 : -1;
  return monitors.slice().sort((left, right) => {
    const leftValue = monitorSortValue(left, state.monitorSort.key, aggregates.get(left.id));
    const rightValue = monitorSortValue(right, state.monitorSort.key, aggregates.get(right.id));
    if (leftValue === null && rightValue === null) return 0;
    if (leftValue === null) return 1;
    if (rightValue === null) return -1;
    let result;
    if (typeof leftValue === 'number' && typeof rightValue === 'number') {
      result = leftValue - rightValue;
    } else {
      result = String(leftValue).localeCompare(String(rightValue), undefined, { numeric: true, sensitivity: 'base' });
    }
    if (result === 0) {
      return String(left.name || '').localeCompare(String(right.name || ''), undefined, { numeric: true, sensitivity: 'base' });
    }
    return result * direction;
  });
}

function syncMonitorSortHeaders() {
  const labels = {
    name: 'monitor name',
    type: 'type',
    target: 'target',
    scope: 'scope',
    interval: 'interval',
    status: 'last status',
    checked: 'last checked',
  };
  for (const header of document.querySelectorAll('#view-monitoring th[data-sort]')) {
    const key = header.dataset.sort;
    const active = key === state.monitorSort.key;
    header.setAttribute('aria-sort', active ? (state.monitorSort.dir === 'asc' ? 'ascending' : 'descending') : 'none');
    header.title = 'Sort by ' + (labels[key] || key);
  }
}

function setMonitorSort(key) {
  if (!key) return;
  if (state.monitorSort.key === key) {
    state.monitorSort.dir = state.monitorSort.dir === 'asc' ? 'desc' : 'asc';
  } else {
    state.monitorSort.key = key;
    state.monitorSort.dir = ['status', 'checked', 'interval'].includes(key) ? 'desc' : 'asc';
  }
  renderMonitoring();
}

function syncMonitorSelection() {
  const monitorIDs = new Set(state.monitors.map((monitor) => monitor.id));
  for (const id of Array.from(state.selectedMonitors)) {
    if (!monitorIDs.has(id)) state.selectedMonitors.delete(id);
  }
  for (const checkbox of document.querySelectorAll('.monitor-select')) {
    checkbox.checked = state.selectedMonitors.has(checkbox.dataset.monitorId);
  }
  const total = state.monitors.length;
  const count = state.selectedMonitors.size;
  const enabledCount = state.monitors.filter((monitor) => state.selectedMonitors.has(monitor.id) && monitor.enabled).length;
  const selectAll = $('monitors-select-all');
  if (selectAll) {
    selectAll.checked = total > 0 && count === total;
    selectAll.indeterminate = count > 0 && count < total;
  }
  for (const [id, label] of [
    ['monitor-bulk-edit', 'Update selected'],
    ['monitor-enable-selected', 'Enable selected'],
    ['monitor-disable-selected', 'Disable selected'],
  ]) {
    const node = $(id);
    if (!node) continue;
    node.disabled = count === 0;
    node.textContent = count ? label + ' (' + count + ')' : label;
  }
  const check = $('monitor-check-selected');
  if (check) {
    check.disabled = enabledCount === 0;
    check.textContent = enabledCount ? 'Check selected (' + enabledCount + ')' : 'Check selected';
    check.title = enabledCount ? '' : 'No enabled monitors selected';
  }
}

function setAllMonitorSelection(checked) {
  state.selectedMonitors.clear();
  if (checked) {
    for (const monitor of state.monitors) state.selectedMonitors.add(monitor.id);
  }
  syncMonitorSelection();
}

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

function showApp() {
  $('auth-screen').classList.add('hidden');
  $('app').classList.remove('hidden');
}

function closeAllModals() {
  while (modalStack.length) {
    modalStack[modalStack.length - 1].close();
  }
}

function showAuthScreenShell() {
  closeAllModals();
  $('app').classList.add('hidden');
  $('auth-screen').classList.remove('hidden');
}

function showAuthMessage(message, ok = false) {
  const node = $('auth-message');
  node.textContent = message;
  node.classList.toggle('ok', ok);
  node.classList.remove('hidden');
}

function clearAuthMessage() {
  const node = $('auth-message');
  node.textContent = '';
  node.classList.remove('ok');
  node.classList.add('hidden');
}

function showAuthStep(id) {
  for (const node of document.querySelectorAll('.auth-step')) {
    node.classList.add('hidden');
  }
  $(id).classList.remove('hidden');
}

function updateUserDisplay() {
  const user = state.auth.user;
  $('current-user').textContent = user?.username || '—';
  $('current-user-role').textContent = user?.mfa_enabled ? 'Password + MFA' : 'MFA not configured';
}

function setView(view) {
  state.view = view;
  const sections = ['dashboard', 'hosts', 'audit', 'monitoring', 'schedules'];
  const labels = { dashboard: 'Overview', hosts: 'Hosts', audit: 'Audit log', monitoring: 'Monitoring', schedules: 'Schedules' };
  for (const section of sections) {
    $('view-' + section).classList.toggle('hidden', section !== view);
  }
  for (const button of document.querySelectorAll('.nav-item[data-view]')) {
    button.classList.toggle('active', button.dataset.view === view);
  }
  $('crumb-view').textContent = labels[view] || 'Overview';
  if (view === 'monitoring') renderMonitoring();
  if (view === 'schedules') renderSchedules();
}

async function api(path, options = {}) {
  const headers = withDemoSession(new Headers(options.headers || {}));
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...options, headers, cache: 'no-store', credentials: 'same-origin' });
  const demoTicket = response.headers.get(demoSessionHeader);
  if (demoTicket) setDemoSession(demoTicket);
  const text = await response.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (!response.ok) {
    const sessionExpired = response.status === 401 && data.code === 'login_required';
    const mfaNeeded = response.status === 403 && data.code === 'mfa_required';
    if (sessionExpired || mfaNeeded) {
      if (sessionExpired) setDemoSession('');
      showAuthScreen();
    }
    const error = new Error(data.error || ('HTTP ' + response.status));
    error.data = data;
    error.status = response.status;
    throw error;
  }
  return data;
}

async function fetchAuthStatus() {
  const headers = withDemoSession(new Headers());
  const response = await fetch('/api/v1/auth/status', { cache: 'no-store', credentials: 'same-origin', headers });
  const demoTicket = response.headers.get(demoSessionHeader);
  if (demoTicket) setDemoSession(demoTicket);
  const text = await response.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (!response.ok) {
    throw new Error(data.error || ('HTTP ' + response.status));
  }
  if (!data.authenticated && !data.mfa_required) setDemoSession('');
  return data;
}

async function showAuthScreen() {
  showAuthScreenShell();
  clearAuthMessage();
  try {
    const status = await fetchAuthStatus();
    state.auth = status;
    await renderAuth(status);
  } catch (error) {
    showAuthStep('login-form');
    $('auth-subtitle').textContent = 'Sign in to manage your fleet.';
    showAuthMessage(error.message);
  }
}

async function renderAuth(status) {
  state.auth = status;
  state.demo = status.demo || null;
  renderDemoLogin();
  if (status.authenticated) {
    stopDemoCodePolling();
    await enterApp();
    return;
  }
  if (status.setup_required) {
    $('auth-subtitle').textContent = 'Create the local administrator account.';
    showAuthStep('setup-form');
    $('setup-username').focus();
    return;
  }
  if (status.mfa_required) {
    if (status.mfa_enrollment_required) {
      $('auth-subtitle').textContent = 'Protect this account with a second factor.';
      showAuthStep('enroll-step');
      await renderEnrollment(status);
    } else {
      $('auth-subtitle').textContent = 'One more step to sign in.';
      showAuthStep('mfa-step');
      renderMFA(status);
    }
    return;
  }
  $('auth-subtitle').textContent = 'Sign in to manage your fleet.';
  showAuthStep('login-form');
  $('login-username').focus();
}

async function enterApp() {
  stopDemoCodePolling();
  showApp();
  updateUserDisplay();
  await loadAll();
  jobPollingStopped = false;
  await loadJobs({ silent: true });
  setAutoRefresh(autoRefreshState.enabled);
  scheduleJobPoll();
}

function updateDemoCode() {
  if (!state.demo) return;
  $('demo-totp-secret').textContent = state.demo.totp_secret || '—';
  $('demo-totp-code').textContent = state.demo.totp_code || '------';
  const remaining = Number(state.demo.totp_remaining_seconds || 0);
  $('demo-totp-remaining').textContent = remaining > 0 ? 'refreshes in ' + remaining + 's' : '';
}

function startDemoCodePolling() {
  if (demoCodeTimer || !state.demo) return;
  demoCodeTimer = window.setInterval(async () => {
    try {
      const previousCode = state.demo ? state.demo.totp_code : '';
      const status = await fetchAuthStatus();
      if (status.demo) {
        state.demo = status.demo;
        updateDemoCode();
        // Keep an untouched auto-filled code current. Do not overwrite a code
        // the visitor typed manually.
        const field = $('totp-code');
        if (!$('totp-form').classList.contains('hidden') && field.value === previousCode) {
          field.value = state.demo.totp_code || '';
        }
      }
    } catch (error) {
      // The auth screen handles its own errors.
    }
  }, 5000);
}

function stopDemoCodePolling() {
  if (demoCodeTimer) {
    window.clearInterval(demoCodeTimer);
    demoCodeTimer = null;
  }
}

function renderDemoLogin() {
  const box = $('demo-login');
  if (!box) return;
  if (!state.demo) {
    box.classList.add('hidden');
    stopDemoCodePolling();
    return;
  }
  box.classList.remove('hidden');
  updateDemoCode();
  startDemoCodePolling();
}

function fillDemoCredentials() {
  if (!state.demo) return;
  $('login-username').value = state.demo.username || 'guest';
  $('login-password').value = state.demo.password || 'guest';
  if (!$('totp-form').classList.contains('hidden')) {
    $('totp-code').value = state.demo.totp_code || '';
    $('totp-code').focus();
    return;
  }
  if (!$('login-form').classList.contains('hidden')) {
    $('login-password').focus();
  }
}

async function demoLogin() {
  if (demoLoginBusy || !state.demo) return;
  const button = $('demo-fill');
  const label = button.textContent;
  demoLoginBusy = true;
  button.disabled = true;
  button.textContent = 'Signing in…';
  clearAuthMessage();
  try {
    const username = state.demo.username || 'guest';
    const password = state.demo.password || 'guest';
    $('login-username').value = username;
    $('login-password').value = password;
    await api('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    $('login-password').value = '';
    let status = await fetchAuthStatus();
    state.auth = status;
    state.demo = status.demo || state.demo;
    updateDemoCode();
    let completedTOTP = false;
    if (status.mfa_required && !status.mfa_enrollment_required &&
        status.user && status.user.totp_enabled && state.demo) {
      // Fetching the status above gives us a fresh code even if the page has
      // been open for a while.
      await api('/api/v1/auth/totp/verify', {
        method: 'POST',
        body: JSON.stringify({ code: state.demo.totp_code || '' }),
      });
      completedTOTP = true;
      status = await fetchAuthStatus();
    }
    if (completedTOTP && !status.authenticated) {
      await renderAuth(status);
      showAuthMessage('Sign-in succeeded but the browser did not keep the demo session cookie. Allow cookies for this site and use the same http:// or https:// address as HIBP_DEMO_PUBLIC_URL.');
      return;
    }
    await renderAuth(status);
  } catch (error) {
    try {
      await showAuthScreen();
    } catch (screenError) {
      // Keep the current screen if the status request also fails.
    }
    showAuthMessage(error.message);
  } finally {
    demoLoginBusy = false;
    button.disabled = false;
    button.textContent = label;
  }
}

function renderMFA(status) {
  const user = status.user || {};
  const methods = [];
  if (user.totp_enabled) methods.push('authenticator code');
  if (user.passkey_count > 0) methods.push('passkey');
  $('mfa-message').textContent = methods.length
    ? 'Enter your ' + methods.join(' or ') + '.'
    : 'No second factor is configured.';
  $('totp-form').classList.toggle('hidden', !user.totp_enabled);
  const passkeyAvailable = Boolean(status.webauthn_available && user.passkey_count > 0);
  $('passkey-login').classList.toggle('hidden', !passkeyAvailable);
  const note = $('mfa-webauthn-note');
  if (user.passkey_count > 0 && !status.webauthn_available) {
    note.textContent = status.webauthn_error || 'Passkeys require opening HIBP via http://localhost:<port>.';
    note.classList.remove('hidden');
  } else {
    note.classList.add('hidden');
  }
  if (user.totp_enabled) $('totp-code').focus();
  if (state.demo) fillDemoCredentials();
}

async function renderEnrollment(status) {
  const user = status.user || {};
  const totpEnabled = Boolean(user.totp_enabled);
  $('enroll-totp').classList.toggle('hidden', totpEnabled);
  $('totp-status').classList.toggle('hidden', !totpEnabled);
  $('totp-qr').classList.add('hidden');
  $('totp-secret').classList.add('hidden');
  $('passkey-note').textContent = status.webauthn_available
    ? ''
    : (status.webauthn_error || 'Passkeys require opening HIBP via http://localhost:<port>.');
  $('passkey-register').disabled = !status.webauthn_available;
  $('enroll-continue').classList.toggle('hidden', !user.mfa_enabled);
  if (!totpEnabled) {
    await startTOTPEnrollment();
  }
}

async function startTOTPEnrollment() {
  if (state.totpSetup) {
    renderTOTPSetup();
    return;
  }
  try {
    state.totpSetup = await api('/api/v1/auth/totp/begin', { method: 'POST' });
    renderTOTPSetup();
  } catch (error) {
    showAuthMessage(error.message);
  }
}

function renderTOTPSetup() {
  if (!state.totpSetup) return;
  $('totp-qr').src = state.totpSetup.qr_png;
  $('totp-qr').classList.remove('hidden');
  $('totp-secret').textContent = String(state.totpSetup.secret || '').replace(/(.{4})/g, '$1 ').trim();
  $('totp-secret').classList.remove('hidden');
  $('totp-enroll-form').classList.remove('hidden');
}

function passkeySupported() {
  return Boolean(window.PublicKeyCredential &&
    typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function' &&
    typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function');
}

async function registerPasskey() {
  clearAuthMessage();
  if (!passkeySupported()) {
    showAuthMessage('This browser cannot use passkeys. Use TOTP or update the browser.');
    return;
  }
  try {
    const options = await api('/api/v1/auth/passkey/register/begin', { method: 'POST' });
    const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey);
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential || typeof credential.toJSON !== 'function') {
      throw new Error('Passkey creation failed.');
    }
    const result = await api('/api/v1/auth/passkey/register/finish', {
      method: 'POST',
      body: JSON.stringify({
        ceremony_id: options.ceremony_id,
        credential: credential.toJSON(),
        name: 'Passkey',
      }),
    });
    state.auth.user = state.auth.user || {};
    state.auth.user.passkey_count = result.passkey_count;
    state.auth.user.mfa_enabled = true;
    state.auth.mfa_enrollment_required = false;
    $('enroll-continue').classList.remove('hidden');
    showAuthMessage('Passkey added.', true);
  } catch (error) {
    showAuthMessage(error.name === 'NotAllowedError' ? 'Passkey prompt was cancelled.' : error.message);
  }
}

async function loginWithPasskey() {
  clearAuthMessage();
  if (!passkeySupported()) {
    showAuthMessage('This browser cannot use passkeys. Use TOTP or update the browser.');
    return;
  }
  try {
    const options = await api('/api/v1/auth/passkey/login/begin', { method: 'POST' });
    const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey);
    const credential = await navigator.credentials.get({ publicKey });
    if (!credential || typeof credential.toJSON !== 'function') {
      throw new Error('Passkey login failed.');
    }
    await api('/api/v1/auth/passkey/login/finish', {
      method: 'POST',
      body: JSON.stringify({
        ceremony_id: options.ceremony_id,
        credential: credential.toJSON(),
      }),
    });
    await showAuthScreen();
  } catch (error) {
    showAuthMessage(error.name === 'NotAllowedError' ? 'Passkey prompt was cancelled.' : error.message);
  }
}

async function signOut() {
  if (autoRefreshState.timer) {
    window.clearInterval(autoRefreshState.timer);
    autoRefreshState.timer = null;
  }
  jobPollingStopped = true;
  if (jobPollTimer) {
    window.clearTimeout(jobPollTimer);
    jobPollTimer = null;
  }
  jobDockState.open = false;
  jobDockState.expanded = true;
  jobDockState.lastActiveCount = 0;
  try {
    await api('/api/v1/auth/logout', { method: 'POST', body: '{}' });
  } catch (error) {
    // The cookie is cleared server-side even if the session had already expired.
  }
  setDemoSession('');
  state.passwords.clear();
  state.sudoPasswords.clear();
  state.sharedSudoPassword = '';
  state.sharedSudoUsername = '';
  state.totpSetup = null;
  state.demo = null;
  state.auth = { user: null, setupRequired: false, authenticated: false, mfaRequired: false, enrollmentRequired: false, webauthnAvailable: false };
  stopDemoCodePolling();
  await showAuthScreen();
}

async function loadAll(options = {}) {
  if (autoRefreshState.loading && !options.force) return;
  autoRefreshState.loading = true;
  try {
    const [status, hosts, audit, monitors, alerts, events, schedules, runs, jobs] = await Promise.all([
      api('/api/v1/status'),
      api('/api/v1/hosts'),
      api('/api/v1/audit?limit=200'),
      api('/api/v1/monitors'),
      api('/api/v1/alerts?limit=200'),
      api('/api/v1/events?limit=200'),
      api('/api/v1/schedules'),
      api('/api/v1/runs?limit=100'),
      api('/api/v1/jobs?limit=40'),
    ]);
    state.status = status;
    state.hosts = hosts.hosts || [];
    state.audit = audit.entries || [];
    state.monitors = monitors.monitors || [];
    state.alerts = alerts.alerts || [];
    state.events = events.events || [];
    state.jobs = jobs.jobs || [];
    state.schedules = schedules.schedules || [];
    state.runs = runs.runs || [];
    renderAll();
    renderOperationBar();
    $('last-refresh').textContent = 'updated ' + new Date().toLocaleTimeString();
  } catch (error) {
    if (error.status === 401) {
      if (autoRefreshState.timer) {
        window.clearInterval(autoRefreshState.timer);
        autoRefreshState.timer = null;
      }
    } else if (!options.silent) {
      toast(error.message, 'error');
    }
  } finally {
    autoRefreshState.loading = false;
  }
}

function renderAll() {
  renderStatus();
  renderStats();
  renderHosts();
  renderAudit();
  renderMonitoring();
  renderSchedules();
  renderJobs();
}

async function loadJobs(options = {}) {
  if (jobDockState.loading) return;
  jobDockState.loading = true;
  try {
    const hadActive = activeJobs().length > 0;
    const data = await api('/api/v1/jobs?limit=40');
    state.jobs = data.jobs || [];
    const summary = currentJobSummary();
    if (summary) {
      const needsDetail = !state.jobDetail ||
        state.jobDetail.id !== summary.id ||
        state.jobDetail.status !== summary.status ||
        summary.status === 'running' ||
        summary.status === 'queued';
      if (needsDetail) {
        const detail = await api('/api/v1/jobs/' + encodeURIComponent(summary.id));
        state.jobDetail = detail.job || null;
      }
    } else {
      state.jobDetail = null;
    }
    renderJobs();
    if (hadActive && activeJobs().length === 0) {
      await loadAll({ silent: true, force: true });
    }
  } catch (error) {
    if (error.status === 401) {
      jobPollingStopped = true;
      if (jobPollTimer) window.clearTimeout(jobPollTimer);
      jobPollTimer = null;
      return;
    }
    if (!options.silent) toast(error.message, 'error');
  } finally {
    jobDockState.loading = false;
  }
}

function currentJobSummary() {
  const jobs = state.jobs || [];
  return jobs.find((job) => job.status === 'running') ||
    jobs.find((job) => job.status === 'queued') ||
    jobs[0] || null;
}

function scheduleJobPoll() {
  if (jobPollingStopped) return;
  if (jobPollTimer) window.clearTimeout(jobPollTimer);
  const active = (state.jobs || []).some((job) => job.status === 'running' || job.status === 'queued');
  jobPollTimer = window.setTimeout(async () => {
    await loadJobs({ silent: true });
    scheduleJobPoll();
  }, active ? 1500 : 10000);
}

function activeJobs() {
  return (state.jobs || []).filter((job) => job.status === 'running' || job.status === 'queued');
}

function jobPercent(job) {
  if (!job || !job.total) return 0;
  if (job.status === 'succeeded') return 100;
  return Math.max(0, Math.min(100, Math.round((Number(job.completed || 0) / Number(job.total || 1)) * 100)));
}

function jobElapsedText(job) {
  const start = job.started_at || job.created_at;
  if (!start) return '';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(start).getTime()) / 1000));
  return operationElapsed(seconds);
}

function jobRunningTarget(job) {
  return (job.targets || []).find((target) => target.status === 'running');
}

function jobSubtitle(job) {
  if (!job) return '—';
  const running = jobRunningTarget(job);
  if (job.cancel_requested && (job.status === 'running' || job.status === 'queued')) {
    return 'Stopping after the current host…';
  }
  if (running) {
    return (running.stage ? running.stage + ' · ' : '') + running.host_name +
      ' · ' + job.completed + ' of ' + job.total + ' hosts';
  }
  if (job.status === 'queued') {
    return 'Queued · ' + job.total + ' host' + (job.total === 1 ? '' : 's');
  }
  const elapsed = jobElapsedText(job);
  return (job.detail || job.status) + (elapsed ? ' · ' + elapsed : '');
}

function jobStatusClass(status) {
  if (status === 'running') return 'running';
  if (status === 'queued') return 'queued';
  if (status === 'succeeded') return 'succeeded';
  if (status === 'failed') return 'failed';
  if (status === 'cancelled') return 'cancelled';
  if (status === 'interrupted') return 'interrupted';
  return 'queued';
}

function jobTargetPillClass(status) {
  if (status === 'succeeded') return 'reachable';
  if (status === 'failed') return 'unreachable';
  if (status === 'running') return 'unknown';
  if (status === 'skipped' || status === 'cancelled' || status === 'interrupted') return 'review';
  return 'unknown';
}

function jobTargetLabel(target) {
  const labels = {
    pending: 'pending', running: 'running', succeeded: 'done', failed: 'failed',
    skipped: 'skipped', cancelled: 'cancelled', interrupted: 'interrupted',
  };
  return labels[target.status] || target.status || 'pending';
}

function jobTargetDetail(target) {
  if (target.stage && target.status === 'running') return target.stage;
  return target.detail || target.error || target.stage || '—';
}

function targetPreview(target) {
  const result = target && target.result;
  return result && result.preview ? result : null;
}

function targetCleanupResult(target) {
  const result = target && target.result;
  if (!result || !Array.isArray(result.packages)) return null;
  return result;
}

function renderJobs() {
  const dock = $('job-dock');
  if (!dock) return;
  const jobs = state.jobs || [];
  const active = activeJobs();
  const summaryJob = currentJobSummary();
  const current = state.jobDetail && summaryJob && state.jobDetail.id === summaryJob.id &&
    (state.jobDetail.status === summaryJob.status || summaryJob.status === 'running' || summaryJob.status === 'queued')
    ? state.jobDetail
    : summaryJob;
  const count = $('activity-count');
  if (count) {
    count.textContent = String(active.length);
    count.classList.toggle('hidden', active.length === 0);
  }
  if (!current) {
    dock.classList.add('hidden');
    return;
  }
  if (active.length > 0 && (jobDockState.lastActiveCount || 0) === 0) {
    jobDockState.open = true;
    jobDockState.expanded = true;
  }
  jobDockState.lastActiveCount = active.length;
  if (!jobDockState.open) {
    dock.classList.add('hidden');
    return;
  }
  dock.classList.remove('hidden');
  dock.className = 'job-dock ' + jobStatusClass(current.status) +
    (jobDockState.expanded ? '' : ' collapsed');
  const running = jobRunningTarget(current);
  $('job-dock-title').textContent = current.title;
  $('job-dock-sub').textContent = jobSubtitle(current);
  $('job-dock-percent').textContent = jobPercent(current) + '%';
  $('job-dock-fill').style.width = jobPercent(current) + '%';
  const status = $('job-dock-status');
  status.textContent = current.status === 'succeeded' ? '✓' :
    current.status === 'failed' ? '!' :
    current.status === 'running' ? '' :
    current.status === 'queued' ? '…' : '!';
  $('job-dock-minimize').textContent = jobDockState.expanded ? '−' : '+';
  $('job-dock-minimize').title = jobDockState.expanded ? 'Minimize activity' : 'Expand activity';

  const summary = $('job-dock-summary');
  summary.textContent = [
    current.completed + ' of ' + current.total + ' hosts',
    current.package ? current.package.name : '',
    current.failed ? current.failed + ' failed' : '',
    current.skipped ? current.skipped + ' skipped' : '',
    jobElapsedText(current),
    active.length > 1 ? (active.length - 1) + ' more queued' : '',
  ].filter(Boolean).join(' · ');

  const list = $('job-dock-list');
  list.replaceChildren();
  const targets = current.targets || [];
  if (!targets.length) {
    list.append(el('div', 'job-dock-empty', current.status === 'running' || current.status === 'queued'
      ? 'Loading host details…'
      : 'No targets.'));
  }
  for (const target of targets) {
    const row = el('div', 'job-dock-row');
    row.append(el('div', 'job-dock-host', target.host_name || target.host_id));
    const pill = el('span', 'pill ' + jobTargetPillClass(target.status), jobTargetLabel(target));
    row.append(pill);
    const detail = el('div', 'job-dock-detail', jobTargetDetail(target));
    detail.title = target.detail || target.error || '';
    row.append(detail);
    const actions = el('div', 'job-dock-row-actions');
    if (current.kind === 'patch-preview' && target.preview_total > 0) {
      actions.append(dockButton('Review', () => reviewPatchTarget(current, target)));
    }
    if (current.kind === 'cleanup-preview' && target.cleanup_count > 0) {
      actions.append(dockButton('Review', () => reviewCleanupTarget(current, target)));
    }
    if (target.has_output && target.status !== 'pending' && target.status !== 'running') {
      actions.append(dockButton('Output', () => showJobOutputModal(current, target)));
    }
    if (actions.childElementCount) row.append(actions);
    else row.append(el('div', 'job-dock-row-actions'));
    list.append(row);
  }

  const actions = $('job-dock-actions');
  actions.replaceChildren();
  if (current.status === 'running' || current.status === 'queued') {
    if (current.cancel_requested) {
      const stopping = dockButton('Stopping after current host…', () => {}, 'danger');
      stopping.disabled = true;
      actions.append(stopping);
    } else {
      actions.append(dockButton(current.status === 'running' ? 'Stop after current host' : 'Cancel', () => cancelJob(current), 'danger'));
    }
  } else {
    if (current.status === 'failed' || current.status === 'interrupted' ||
        current.status === 'cancelled' || (current.status === 'succeeded' && current.skipped > 0)) {
      if (current.kind === 'patch-apply') {
        actions.append(dockButton('New preview', () => createJob('patch-preview', (current.targets || []).map((target) => target.host_id)), 'primary'));
      }
      actions.append(dockButton('Retry skipped/failed', () => retryJob(current)));
    }
    if (current.kind === 'patch-preview' && (current.targets || []).some((target) => target.preview_total > 0)) {
      actions.append(dockButton('Review & apply', () => reviewPatchJob(current), 'primary'));
    }
    if (current.kind === 'cleanup-preview' && (current.targets || []).some((target) => target.cleanup_count > 0)) {
      actions.append(dockButton('Review cleanup', () => reviewCleanupJob(current), 'primary'));
    }
    actions.append(dockButton('Dismiss', () => dismissJob(current)));
  }
}

function dockButton(label, handler, cls = '') {
  const button = el('button', 'btn ' + cls, label);
  button.type = 'button';
  button.addEventListener('click', handler);
  return button;
}

async function showJobOutputModal(job, target) {
  const detail = await jobWithTargets(job);
  const fullTarget = (detail.targets || []).find((entry) => entry.host_id === target.host_id) || target;
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', job.title + ' · ' + target.host_name));
  const text = [fullTarget.output, fullTarget.error].filter(Boolean).join('\n\n') || 'No output.';
  body.append(el('pre', 'cleanup-list', text));
  const actions = el('div', 'modal-actions');
  const closeButton = el('button', 'btn', 'Close');
  closeButton.type = 'button';
  actions.append(closeButton);
  body.append(actions);
  const close = openModal('Operation output — ' + target.host_name, body, null, 'wide');
  closeButton.addEventListener('click', close);

  if (job.kind === 'patch-preview') {
    const previews = (detail.targets || []).filter((entry) => {
      const preview = targetPreview(entry);
      return preview && previewTotal(preview.preview) > 0;
    });
    if (previews.length > 1) {
      actions.prepend(dockButton('Review & apply all hosts', async () => {
        close();
        await reviewPatchJob(job);
      }, 'primary'));
    } else if (targetPreview(fullTarget) && previewTotal(targetPreview(fullTarget).preview) > 0) {
      actions.prepend(dockButton('Review & apply', async () => {
        close();
        await reviewPatchTarget(job, fullTarget);
      }, 'primary'));
    }
  }
}

async function createJob(kind, hosts, options = {}) {
  const list = Array.isArray(hosts) ? hosts : [];
  if (!list.length) {
    toast('Select at least one host', 'error');
    return null;
  }
  const payload = {
    kind,
    host_ids: list.map((host) => host.id || host),
    ...options,
  };
  try {
    const result = await api('/api/v1/jobs', { method: 'POST', body: JSON.stringify(payload) });
    jobDockState.open = true;
    jobDockState.expanded = true;
    await loadJobs({ silent: true });
    toast('Queued: ' + result.job.title, 'ok');
    return result.job;
  } catch (error) {
    toast(error.message, 'error');
    return null;
  }
}

async function cancelJob(job) {
  try {
    await api('/api/v1/jobs/' + encodeURIComponent(job.id) + '/cancel', { method: 'POST', body: '{}' });
    toast(job.status === 'queued' ? 'Job cancelled' : 'Stopping after the current host', 'ok');
    await loadJobs({ silent: true });
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function retryJob(job) {
  try {
    await api('/api/v1/jobs/' + encodeURIComponent(job.id) + '/retry', { method: 'POST', body: '{}' });
    toast('Job queued for retry', 'ok');
    await loadJobs({ silent: true });
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function dismissJob(job) {
  try {
    await api('/api/v1/jobs/' + encodeURIComponent(job.id), { method: 'DELETE' });
    if ((state.jobs || []).length <= 1) jobDockState.open = false;
    await loadJobs({ silent: true });
  } catch (error) {
    toast(error.message, 'error');
  }
}

function hostById(id) {
  return (state.hosts || []).find((host) => host.id === id);
}

async function reviewPatchJob(job) {
  const detail = await jobWithTargets(job);
  const previews = new Map();
  const hosts = [];
  for (const target of detail.targets || []) {
    const result = targetPreview(target);
    if (!result) continue;
    const host = hostById(target.host_id);
    if (!host) continue;
    hosts.push(host);
    previews.set(host.id, { preview: result.preview, preview_hash: result.preview_hash });
  }
  if (!previews.size) {
    toast('No reviewed previews are available', 'error');
    return;
  }
  showPatchReview(hosts, previews);
}

async function reviewPatchTarget(job, target) {
  const detail = await jobWithTargets(job);
  const fullTarget = (detail.targets || []).find((entry) => entry.host_id === target.host_id) || target;
  const result = targetPreview(fullTarget);
  const host = hostById(target.host_id);
  if (!result || !host) {
    toast('This preview is no longer available; run the preview again', 'error');
    return;
  }
  const previews = new Map([[host.id, { preview: result.preview, preview_hash: result.preview_hash }]]);
  showPatchReview([host], previews);
}

async function jobWithTargets(job) {
  if (job.targets && job.targets.length && job.targets.some((target) =>
    target.result || target.output || target.error)) {
    return job;
  }
  try {
    const data = await api('/api/v1/jobs/' + encodeURIComponent(job.id) + '?full=1');
    if (data.job) {
      state.jobDetail = data.job;
      renderJobs();
      return data.job;
    }
  } catch (error) {
    toast(error.message, 'error');
  }
  return job;
}

async function reviewCleanupJob(job) {
  const detail = await jobWithTargets(job);
  const entries = [];
  for (const target of detail.targets || []) {
    const result = targetCleanupResult(target);
    if (!result || !result.count) continue;
    const host = hostById(target.host_id);
    if (host) entries.push({ host, result });
  }
  if (!entries.length) {
    toast('No reviewed cleanup list is available', 'error');
    return;
  }
  showCleanupReview(entries);
}

async function reviewCleanupTarget(job, target) {
  const detail = await jobWithTargets(job);
  const fullTarget = (detail.targets || []).find((entry) => entry.host_id === target.host_id) || target;
  const result = targetCleanupResult(fullTarget);
  const host = hostById(target.host_id);
  if (!result || !host) {
    toast('This cleanup preview is no longer available; scan again', 'error');
    return;
  }
  showCleanupReview([{ host, result }]);
}

function renderStatus() {
  const banner = $('demo-banner');
  if (banner) banner.classList.toggle('hidden', !state.status.demo);
  const build = state.status.build || { version: state.status.version };
  const full = buildIdentity(build);
  $('server-version').textContent = 'HIBP ' + (versionLabel(build.version) || 'dev');
  $('server-version').title = full;
  const buildParts = [];
  if (build.build_number) buildParts.push('build ' + build.build_number);
  if (build.build_commit) buildParts.push('commit ' + build.build_commit);
  $('server-build').textContent = buildParts.join(' · ') || 'build unknown';
  $('server-build').title = full;
  $('server-hosts').textContent = (state.hosts.length) + ' hosts';
  $('server-time').textContent = state.status.time ? new Date(state.status.time).toLocaleTimeString() : '—';
  $('nav-host-count').textContent = String(state.hosts.length);
  updateUserDisplay();
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
  syncHostSelection();
}

function hostRow(host) {
  const tr = el('tr');
  const facts = host.facts || {};

  const selectTd = el('td');
  const select = el('input', 'row-select host-select');
  select.type = 'checkbox';
  select.dataset.hostId = host.id;
  select.checked = state.selectedHosts.has(host.id);
  select.title = 'Select ' + host.name + ' for a helper update';
  select.setAttribute('aria-label', select.title);
  select.addEventListener('change', () => {
    if (select.checked) state.selectedHosts.add(host.id);
    else state.selectedHosts.delete(host.id);
    syncHostSelection();
  });
  selectTd.append(select);

  const hostTd = el('td');
  const hostCell = el('div', 'host-cell');
  const hostIcon = el('div', 'host-ico');
  hostIcon.append(icon('host'));
  const hostText = el('div');
  const hostName = el('div', 'host-name');
  hostName.append(document.createTextNode(host.name));
  if (Number(host.docker_project_count || 0) > 0 || Number(host.docker_container_count || 0) > 0) {
    const dockerToggle = el('button', 'host-docker-toggle', '+');
    dockerToggle.type = 'button';
    dockerToggle.title = 'Open Docker containers for ' + host.name;
    dockerToggle.setAttribute('aria-label', dockerToggle.title);
    dockerToggle.addEventListener('click', (event) => {
      event.stopPropagation();
      showHostDetails(host, 'containers');
    });
    hostName.append(dockerToggle);
  }
  hostText.append(hostName, el('div', 'host-ip', host.address + ':' + host.port));
  hostText.classList.add('host-open');
  hostText.title = 'Open host details';
  hostText.tabIndex = 0;
  hostText.setAttribute('role', 'button');
  hostText.addEventListener('click', () => showHostDetails(host));
  hostText.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      showHostDetails(host);
    }
  });
  hostCell.append(hostIcon, hostText);
  hostTd.append(hostCell);

  const osTd = el('td');
  const os = el('div', 'os', facts.os_pretty_name || host.os_family || 'Unknown');
  os.append(el('small', '', facts.kernel || (host.auth_type + ' auth')));
  osTd.append(os);

  const agent = facts.agent || {};
  const agentTd = el('td');
  if (agent.version) {
    const controller = state.status.build || { version: state.status.version };
    const stale = Boolean(controller.version && agent.version !== controller.version) ||
      Boolean(controller.build_commit && agent.build_commit && agent.build_commit !== controller.build_commit);
    const agentEl = el('div', 'agent-version' + (stale ? ' stale' : ''), versionLabel(agent.version));
    const detail = [];
    if (agent.build_number) detail.push('build ' + agent.build_number);
    if (agent.build_commit) detail.push(agent.build_commit);
    if (detail.length) agentEl.append(el('small', '', detail.join(' · ')));
    agentEl.title = buildIdentity(agent) + (stale ? ' — differs from the running controller' : '');
    agentTd.append(agentEl);
  } else {
    agentTd.append(el('span', 'muted', 'not reported'));
    agentTd.title = 'Update the helper or collect facts to report the installed build.';
  }

  const pending = Number(facts.pending_updates || 0);
  const pendingTd = el('td');
  const pendingEl = el('span', 'pending ' + (pending === 0 ? 'zero' : pending >= 5 ? 'high' : 'low'));
  pendingEl.append(el('span', 'count', pending), document.createTextNode(' updates'));
  pendingTd.append(pendingEl);
  const orphaned = Number(facts.orphaned_packages || 0);
  if (facts.cleanup_supported && orphaned > 0) {
    const line = el('div', 'unused-line');
    const badge = el('span', 'badge amber', orphaned + ' unused');
    badge.title = 'Orphaned packages can be removed with Cleanup';
    line.append(badge);
    pendingTd.append(line);
  }

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
  actions.append(actionButton('Services', () => showHostDetails(host, 'services')));
  if (host.auth_type === 'agent') {
    actions.append(actionButton('Agent token', () => showAgentTokenModal(host)));
  } else {
    actions.append(actionButton('Test', () => testHost(host)));
    actions.append(actionButton('Setup', () => bootstrapHost(host)));
    actions.append(actionButton('Facts', () => collectFacts(host)));
    actions.append(actionButton('Patch', () => showPatchModal(host)));
    actions.append(actionButton('Cleanup', () => showCleanupModal(host)));
    actions.append(actionButton('Reboot', () => rebootHost(host), 'danger'));
  }
  actions.append(actionButton('Delete', () => deleteHost(host), 'danger'));
  actionsTd.append(actions);

  tr.append(selectTd, hostTd, osTd, agentTd, pendingTd, checkTd, uptimeTd, rebootTd, statusTd, actionsTd);
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

const MONITOR_TYPES = {
  'host.cpu': {
    label: 'CPU usage', target: 'none', threshold: 'percent',
    warningLabel: 'Warning %', criticalLabel: 'Critical %', warning: 80, critical: 90,
    note: 'Uses the latest collected metric sample. Warning and critical are percentages.',
  },
  'host.memory': {
    label: 'Memory usage', target: 'none', threshold: 'percent',
    warningLabel: 'Warning %', criticalLabel: 'Critical %', warning: 85, critical: 95,
    note: 'Uses the latest collected metric sample. Warning and critical are percentages.',
  },
  'host.disk': {
    label: 'Disk usage', target: 'mount', targetLabel: 'Mount path', placeholder: '/',
    defaultTarget: '/', threshold: 'percent',
    warningLabel: 'Warning %', criticalLabel: 'Critical %', warning: 80, critical: 90,
    note: 'Uses the collected system information for the exact mount path.',
  },
  'host.load': {
    label: 'Load average', target: 'none', threshold: 'number',
    warningLabel: 'Warning load', criticalLabel: 'Critical load', warning: 4, critical: 8,
    note: 'Compares 1-minute load average. Set thresholds relative to the host CPU count.',
  },
  'host.ntp': {
    label: 'NTP clock', target: 'none', threshold: 'number',
    warningLabel: 'Warning offset (s)', criticalLabel: 'Critical offset (s)', warning: 1, critical: 5,
    note: 'Uses the NTP offset and synchronization state collected with facts. Critical when the clock is unsynchronized or the absolute offset exceeds the threshold.',
  },
  'docker.project': {
    label: 'Compose project', target: 'project', targetLabel: 'Compose project',
    placeholder: 'app', threshold: 'none',
    note: 'Critical when no container in the Compose project is running or any container is unhealthy.',
  },
  'docker.container': {
    label: 'Container', target: 'container', targetLabel: 'Container name or *',
    placeholder: 'app-web-1 or *', threshold: 'none',
    note: 'A named container is critical when missing, stopped, or unhealthy. Use * to monitor every container on each assigned host, including stopped containers. The fleet Docker health monitor ignores cleanly stopped containers.',
  },
  'docker.health': {
    label: 'Docker health', target: 'none', threshold: 'none',
    note: 'Fleet-wide Docker health. Critical when a container is unhealthy, restarting, or dead. Cleanly stopped containers are ignored here; use a Container monitor with target * for a strict all-container check.',
  },
  'service.systemd': {
    label: 'systemd service', target: 'service', targetLabel: 'Unit name',
    placeholder: 'nginx.service', threshold: 'none',
    note: 'Uses the systemd snapshot collected with host metrics. Add the .service suffix.',
  },
  'service.baseline': {
    label: 'Service baseline', target: 'none', threshold: 'none',
    note: 'Compares running systemd services with the per-host baseline. Alerts on failed services and expected baseline units that are no longer running. Exclude units or disable monitoring per host from the host Services tab.',
  },
  'security.auth': {
    label: 'Failed authentication', target: 'none', threshold: 'number',
    warningLabel: 'Warning count', criticalLabel: 'Critical count', warning: 5, critical: 10,
    note: 'Counts normalized authentication-failure events collected from journald or auth logs in the configured window. The window is a fleet setting (events.auth_window_minutes, default 10).',
  },
  'http': {
    label: 'HTTP endpoint', target: 'url', targetLabel: 'URL',
    placeholder: 'https://example.com/health', threshold: 'latency',
    warningLabel: 'Warning latency (ms)', criticalLabel: 'Critical latency (ms)', warning: 0, critical: 0,
    namePlaceholder: 'App availability',
    note: '2xx and 3xx responses are healthy. Redirects are followed up to five times. Latency thresholds are optional; 0 disables them. Add a TLS certificate monitor for expiry alerts.',
  },
  'tcp': {
    label: 'TCP port', target: 'address', targetLabel: 'host:port',
    placeholder: '10.0.0.10:443', threshold: 'latency',
    warningLabel: 'Warning latency (ms)', criticalLabel: 'Critical latency (ms)', warning: 0, critical: 0,
    namePlaceholder: 'Database port',
    note: 'A successful TCP connect is healthy. Latency thresholds are optional; 0 disables them.',
  },
  'ssl': {
    label: 'TLS certificate', target: 'address', targetLabel: 'host:port',
    placeholder: 'example.com:443', threshold: 'days',
    warningLabel: 'Warning days left', criticalLabel: 'Critical days left', warning: 30, critical: 14,
    namePlaceholder: 'Certificate expiry',
    note: 'Connects with TLS and checks certificate expiry. Warning must be larger than critical.',
  },
};

const MONITOR_STATUS_RANK = { ok: 0, unknown: 1, warning: 2, critical: 3 };

function monitorTypeLabel(type) {
  return (MONITOR_TYPES[type] && MONITOR_TYPES[type].label) || type;
}

function monitorHostName(hostID) {
  if (!hostID) return 'standalone probe';
  const host = state.hosts.find((entry) => entry.id === hostID);
  return host ? host.name : hostID.slice(0, 8);
}

function isNetworkMonitorType(type) {
  return type === 'http' || type === 'tcp' || type === 'ssl';
}

function monitorAssignmentLabel(assignment) {
  if (assignment.scope === 'fleet') return 'Fleet';
  if (assignment.scope === 'standalone') return 'Standalone';
  if (assignment.scope === 'host') return 'Host: ' + monitorHostName(assignment.target);
  if (assignment.scope === 'group') return 'Group: ' + assignment.target;
  if (assignment.scope === 'tag') return 'Tag: ' + assignment.target;
  return assignment.scope + ': ' + assignment.target;
}

function formatMonitorInterval(seconds) {
  const value = Number(seconds) || 0;
  if (value < 60) return value + 's';
  if (value < 3600) return Math.round(value / 60) + 'm';
  if (value % 3600 === 0) return (value / 3600) + 'h';
  return (value / 3600).toFixed(1) + 'h';
}

function monitorAggregate(monitor) {
  if (!monitor.enabled) {
    return { status: 'unknown', summary: 'disabled', title: 'Monitor is disabled.', detail: '' };
  }
  const states = monitor.states || [];
  if (!states.length) {
    return { status: 'unknown', summary: 'not checked', title: 'No checks recorded yet.', detail: '' };
  }
  const counts = { critical: 0, warning: 0, unknown: 0, ok: 0 };
  let worst = 'ok';
  for (const state of states) {
    const status = Object.prototype.hasOwnProperty.call(counts, state.status) ? state.status : 'unknown';
    counts[status]++;
    if (MONITOR_STATUS_RANK[status] > MONITOR_STATUS_RANK[worst]) worst = status;
  }
  const parts = [];
  if (counts.critical) parts.push(counts.critical + ' critical');
  if (counts.warning) parts.push(counts.warning + ' warning');
  if (counts.unknown) parts.push(counts.unknown + ' unknown');
  if (counts.ok) parts.push(counts.ok + ' ok');
  const title = states
    .map((entry) => monitorHostName(entry.host_id) + ': ' + entry.status + ' — ' + (entry.message || 'no detail'))
    .join('\n');
  const worstState = states
    .filter((entry) => entry.status !== 'ok' && MONITOR_STATUS_RANK[entry.status] === MONITOR_STATUS_RANK[worst])
    .sort((left, right) => monitorHostName(left.host_id).localeCompare(monitorHostName(right.host_id)))[0];
  const detail = worstState
    ? monitorHostName(worstState.host_id) + ': ' + (worstState.message || worstState.status)
    : '';
  return { status: worst, summary: parts.join(' · '), title, detail };
}

// monitorStatusCounts returns enabled monitors grouped by their worst current
// status. Disabled monitors are excluded so they do not inflate the unknown
// counter in the sidebar.
function monitorStatusCounts() {
  const counts = { critical: 0, warning: 0, unknown: 0, ok: 0 };
  for (const monitor of state.monitors || []) {
    if (!monitor.enabled) continue;
    const aggregate = monitorAggregate(monitor);
    const status = Object.prototype.hasOwnProperty.call(counts, aggregate.status) ? aggregate.status : 'unknown';
    counts[status]++;
  }
  return counts;
}

function renderMonitorNavCounts() {
  const counts = monitorStatusCounts();
  const targets = {
    critical: $('nav-monitor-critical'),
    warning: $('nav-monitor-warning'),
    unknown: $('nav-monitor-unknown'),
    ok: $('nav-monitor-ok'),
  };
  for (const [status, node] of Object.entries(targets)) {
    if (node) node.textContent = String(counts[status]);
  }
  const wrapper = $('nav-monitor-counts');
  if (wrapper) {
    wrapper.title = counts.critical + ' critical · ' + counts.warning + ' warning · ' +
      counts.unknown + ' unknown · ' + counts.ok + ' ok (enabled monitors)';
  }
}

function monitorStatusPill(status, label = '') {
  const cls = status === 'ok' ? 'reachable' : status === 'warning' ? 'review' : status === 'critical' ? 'unreachable' : 'unknown';
  return el('span', 'pill ' + cls, '● ' + (label || status));
}

function showMonitorDetails(monitor) {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Latest per-host results. The alert table keeps the full delivery history.'));
  const states = (monitor.states || []).slice().sort((left, right) => {
    const rank = (status) => (Object.prototype.hasOwnProperty.call(MONITOR_STATUS_RANK, status) ? MONITOR_STATUS_RANK[status] : 1);
    return rank(right.status) - rank(left.status) ||
      monitorHostName(left.host_id).localeCompare(monitorHostName(right.host_id));
  });
  if (!monitor.enabled) {
    body.append(el('div', 'empty-state', 'This monitor is disabled. Enable it and run a check to produce results.'));
  } else if (!states.length) {
    body.append(el('div', 'empty-state', 'No checks recorded yet. Use Check on the monitor row to evaluate it now.'));
  } else {
    const wrap = el('div', 'scroll-list');
    const table = el('table');
    const head = el('tr');
    for (const label of ['Host', 'Status', 'Detail', 'Checked', '']) head.append(el('th', '', label));
    table.append(head);
    for (const entry of states) {
      const row = el('tr');
      const statusTd = el('td');
      statusTd.append(monitorStatusPill(entry.status));
      const detailTd = el('td', 'alert-detail', entry.message || '—');
      detailTd.title = entry.message || '';
      const checkedTd = el('td');
      const checked = el('span', 'nowrap', relativeTime(entry.checked_at));
      if (entry.checked_at) checked.title = new Date(entry.checked_at).toLocaleString();
      checkedTd.append(checked);
      const actionTd = el('td');
      const host = entry.host_id ? (state.hosts || []).find((candidate) => candidate.id === entry.host_id) : null;
      if (host) {
        const tab = monitor.type.startsWith('docker.') ? 'containers'
          : monitor.type.startsWith('service.') ? 'services' : 'overview';
        const label = tab === 'containers' ? 'Containers' : tab === 'services' ? 'Services' : 'Host';
        actionTd.append(actionButton(label, () => showHostDetails(host, tab)));
      }
      row.append(el('td', '', monitorHostName(entry.host_id)), statusTd, detailTd, checkedTd, actionTd);
      table.append(row);
    }
    wrap.append(table);
    body.append(wrap);
  }
  const actions = el('div', 'modal-actions');
  const close = el('button', 'btn primary', 'Close');
  close.type = 'button';
  actions.append(close);
  body.append(actions);
  const closeFn = openModal('Monitor details — ' + monitor.name, body, null, 'wide');
  close.addEventListener('click', closeFn);
}

function monitorMapScopeKey(monitor) {
  if (isNetworkMonitorType(monitor.type)) return 'standalone';
  const scopes = new Set((monitor.assignments || []).map((assignment) => assignment.scope));
  if (!scopes.size) return 'standalone';
  if (scopes.size > 1) return 'mixed';
  const scope = Array.from(scopes)[0];
  return ['fleet', 'host', 'group', 'tag'].includes(scope) ? scope : 'other';
}

function monitorMapGroups(monitors, aggregates) {
  const byName = (left, right) => String(left.name || '').localeCompare(String(right.name || ''), undefined, { numeric: true, sensitivity: 'base' });
  let groups;
  if (state.monitorMapGroup === 'type') {
    const known = new Set(Object.keys(MONITOR_TYPES));
    groups = Object.keys(MONITOR_TYPES).map((type) => ({
      key: type,
      label: monitorTypeLabel(type),
      monitors: monitors.filter((monitor) => monitor.type === type),
    })).filter((group) => group.monitors.length);
    const other = monitors.filter((monitor) => !known.has(monitor.type));
    if (other.length) groups.push({ key: 'other', label: 'Other', monitors: other });
  } else if (state.monitorMapGroup === 'scope') {
    const order = [
      ['standalone', 'Standalone'],
      ['fleet', 'Fleet'],
      ['host', 'Host'],
      ['group', 'Group'],
      ['tag', 'Tag'],
      ['mixed', 'Mixed scopes'],
      ['other', 'Other'],
    ];
    groups = order.map(([key, label]) => ({
      key,
      label,
      monitors: monitors.filter((monitor) => monitorMapScopeKey(monitor) === key),
    })).filter((group) => group.monitors.length);
  } else if (state.monitorMapGroup === 'enabled') {
    groups = [
      { key: 'enabled', label: 'Enabled', monitors: monitors.filter((monitor) => monitor.enabled) },
      { key: 'disabled', label: 'Disabled', monitors: monitors.filter((monitor) => !monitor.enabled) },
    ].filter((group) => group.monitors.length);
  } else {
    groups = [
      ['critical', 'Critical'],
      ['warning', 'Warning'],
      ['unknown', 'Unknown'],
      ['ok', 'OK'],
    ].map(([status, label]) => ({
      key: status,
      label,
      status,
      monitors: monitors.filter((monitor) => ((aggregates.get(monitor.id) || {}).status || 'unknown') === status),
    }));
  }
  for (const group of groups) group.monitors.sort(byName);
  return groups;
}

function monitorMapNode(monitor, aggregate) {
  const status = aggregate.status || 'unknown';
  const node = el('button', 'monitor-node status-' + status + (monitor.enabled ? '' : ' disabled'));
  node.type = 'button';
  node.title = monitor.name + ' · ' + monitorTypeLabel(monitor.type) +
    (monitor.target ? ' · ' + monitor.target : '') + '\n' + (aggregate.title || aggregate.summary || status);
  node.setAttribute('aria-label', monitor.name + ', ' + monitorTypeLabel(monitor.type) + ', ' + status + '. Open monitor.');

  const top = el('div', 'monitor-node-top');
  top.append(el('span', 'monitor-node-dot ' + status), el('span', 'monitor-node-name', monitor.name));
  if (!monitor.enabled) top.append(el('span', 'monitor-node-off', 'off'));
  node.append(top);

  const metaParts = [monitorTypeLabel(monitor.type)];
  if (monitor.target) metaParts.push(monitor.target);
  const scope = monitorScopeText(monitor);
  if (scope) metaParts.push(scope);
  const meta = el('div', 'monitor-node-meta', metaParts.join(' · '));
  meta.title = metaParts.join(' · ');
  node.append(meta);

  const foot = el('div', 'monitor-node-foot');
  foot.append(el('span', 'monitor-node-status', aggregate.detail || aggregate.summary || status));
  foot.append(el('span', 'monitor-node-checked', monitor.enabled ? relativeTime(monitor.last_checked_at) : 'disabled'));
  node.append(foot);
  node.addEventListener('click', () => showMonitorModal(monitor));
  return node;
}

function renderMonitorMap(monitors, aggregates) {
  const map = $('monitor-map');
  if (!map) return;
  map.replaceChildren();
  if (!monitors.length) {
    map.append(el('div', 'empty-state', 'No monitors configured. Add a monitor to see it on the map.'));
    return;
  }
  for (const group of monitorMapGroups(monitors, aggregates)) {
    const section = el('section', 'monitor-map-group');
    const head = el('div', 'monitor-map-group-head');
    if (group.status) head.append(el('span', 'map-dot ' + group.status));
    head.append(el('span', '', group.label), el('span', 'monitor-map-group-count', String(group.monitors.length)));
    section.append(head);
    if (group.monitors.length) {
      const grid = el('div', 'monitor-map-grid');
      for (const monitor of group.monitors) {
        grid.append(monitorMapNode(monitor, aggregates.get(monitor.id) || monitorAggregate(monitor)));
      }
      section.append(grid);
    } else {
      section.append(el('div', 'monitor-node-meta', 'No monitors'));
    }
    map.append(section);
  }
}

function emptyTableRow(columns, message) {
  const row = el('tr');
  const cell = el('td', 'empty-state', message);
  cell.colSpan = columns;
  row.append(cell);
  return row;
}

function renderMonitoring() {
  const body = $('monitor-body');
  if (!body) return;
  const monitors = state.monitors || [];
  const alerts = state.alerts || [];
  const aggregates = new Map(monitors.map((monitor) => [monitor.id, monitorAggregate(monitor)]));
  const sorted = sortedMonitors(monitors, aggregates);
  const enabled = monitors.filter((monitor) => monitor.enabled).length;
  const counts = monitorStatusCounts();
  const summary = [];
  summary.push(monitors.length + ' monitor' + (monitors.length === 1 ? '' : 's'));
  summary.push(enabled + ' enabled');
  for (const status of ['critical', 'warning', 'unknown', 'ok']) {
    if (counts[status]) summary.push(counts[status] + ' ' + status);
  }
  $('monitor-summary').textContent = summary.join(' · ');
  renderMonitorNavCounts();
  syncMonitorSortHeaders();
  renderMonitorMap(monitors, aggregates);

  body.replaceChildren();
  if (!monitors.length) {
    body.append(emptyTableRow(9, 'No monitors configured. Add a monitor to watch host metrics, Docker, services, or network endpoints.'));
  }
  const monitorNames = new Map(monitors.map((monitor) => [monitor.id, monitor.name]));
  for (const monitor of sorted) {
    const aggregate = aggregates.get(monitor.id) || monitorAggregate(monitor);
    const row = el('tr');

    const selectTd = el('td');
    const select = el('input', 'row-select monitor-select');
    select.type = 'checkbox';
    select.dataset.monitorId = monitor.id;
    select.checked = state.selectedMonitors.has(monitor.id);
    select.title = 'Select ' + monitor.name;
    select.setAttribute('aria-label', select.title);
    select.addEventListener('change', () => {
      if (select.checked) state.selectedMonitors.add(monitor.id);
      else state.selectedMonitors.delete(monitor.id);
      syncMonitorSelection();
    });
    selectTd.append(select);

    const nameTd = el('td');
    nameTd.append(el('div', 'host-name', monitor.name));
    nameTd.append(el('div', 'host-ip', monitor.enabled ? 'enabled' : 'disabled'));

    const typeTd = el('td', '', monitorTypeLabel(monitor.type));

    const targetTd = el('td');
    const targetText = monitor.target || '—';
    const target = el('span', 'monitor-target', targetText);
    target.title = targetText;
    targetTd.append(target);

    const assignmentTd = el('td');
    const assignmentWrap = el('div', 'assignment-pills');
    const assignments = monitor.assignments || [];
    const network = isNetworkMonitorType(monitor.type);
    if (network || !assignments.length) {
      const standalone = el('span', 'assignment-pill', 'Standalone');
      if (network) standalone.title = 'Runs from the HIBP controller; host assignments do not affect this probe.';
      assignmentWrap.append(standalone);
    }
    if (!network) {
      for (const assignment of assignments) {
        assignmentWrap.append(el('span', 'assignment-pill', monitorAssignmentLabel(assignment)));
      }
    }
    assignmentTd.append(assignmentWrap);

    const intervalTd = el('td', '', formatMonitorInterval(monitor.interval_seconds));

    const statusTd = el('td');
    const statusPill = monitorStatusPill(aggregate.status, aggregate.summary === 'disabled' ? 'disabled' : '');
    statusPill.title = aggregate.title;
    statusTd.append(statusPill);
    const statusText = aggregate.detail ? aggregate.summary + ' · ' + aggregate.detail : aggregate.summary;
    const statusSummary = el('div', 'muted monitor-status-summary', statusText);
    statusSummary.title = aggregate.title;
    statusTd.append(statusSummary);

    const checkedTd = el('td');
    const checked = el('span', 'nowrap', relativeTime(monitor.last_checked_at));
    if (monitor.last_checked_at) checked.title = new Date(monitor.last_checked_at).toLocaleString();
    checkedTd.append(checked);

    const actionsTd = el('td');
    const actions = el('div', 'actions');
    actions.append(actionButton('Edit', () => showMonitorModal(monitor)));
    actions.append(actionButton('Details', () => showMonitorDetails(monitor)));
    const check = actionButton('Check', () => checkMonitorNow(monitor));
    check.disabled = !monitor.enabled;
    if (!monitor.enabled) check.title = 'Enable the monitor first';
    actions.append(check);
    actions.append(actionButton('Delete', () => deleteMonitor(monitor), 'danger'));
    actionsTd.append(actions);

    row.append(selectTd, nameTd, typeTd, targetTd, assignmentTd, intervalTd, statusTd, checkedTd, actionsTd);
    body.append(row);
  }

  const alertBody = $('alert-body');
  alertBody.replaceChildren();
  if (!alerts.length) {
    alertBody.append(emptyTableRow(6, 'No alert events yet. Alerts appear here even when email is disabled or delivery fails.'));
  }
  for (const event of alerts) {
    const row = el('tr');
    const timeTd = el('td');
    const time = el('span', 'nowrap', relativeTime(event.created_at));
    time.title = new Date(event.created_at).toLocaleString();
    timeTd.append(time);
    const monitorTd = el('td', '', monitorNames.get(event.monitor_id) || event.monitor_id.slice(0, 8));
    const hostTd = el('td', '', event.host_id ? monitorHostName(event.host_id) : 'standalone probe');
    const statusTd = el('td');
    statusTd.append(monitorStatusPill(event.status, event.status === 'ok' ? 'recovered' : ''));
    const detailTd = el('td', 'alert-detail', event.detail || '');
    detailTd.title = event.detail || '';
    const emailTd = el('td');
    if (event.emailed) {
      emailTd.append(el('span', 'badge green', 'sent'));
    } else if (event.error) {
      const failed = el('span', 'badge red', 'failed');
      failed.title = event.error;
      emailTd.append(failed);
    } else {
      emailTd.append(el('span', 'badge amber', 'not sent'));
    }
    row.append(timeTd, monitorTd, hostTd, statusTd, detailTd, emailTd);
    alertBody.append(row);
  }

  const eventBody = $('event-body');
  if (eventBody) {
    const events = state.events || [];
    eventBody.replaceChildren();
    if (!events.length) {
      eventBody.append(emptyTableRow(8, 'No security or service events collected yet.'));
    }
    for (const record of events) {
      const row = el('tr');
      const timeTd = el('td');
      const time = el('span', 'nowrap', relativeTime(record.occurred_at));
      time.title = record.occurred_at ? new Date(record.occurred_at).toLocaleString() : '';
      timeTd.append(time);
      const host = (state.hosts || []).find((entry) => entry.id === record.host_id);
      const hostTd = el('td', '', host ? host.name : record.host_id.slice(0, 8));
      const sourceTd = el('td', '', record.source || '—');
      sourceTd.title = record.source || '';
      const categoryTd = el('td', '', record.category || '—');
      const severity = String(record.severity || 'info');
      const severityClass = severity === 'critical' ? 'unreachable' : severity === 'warning' ? 'review' : severity === 'info' ? 'reachable' : 'unknown';
      const severityTd = el('td');
      severityTd.append(el('span', 'pill ' + severityClass, severity));
      const userTd = el('td', '', record.username || '—');
      const ipTd = el('td', '', record.remote_ip || '—');
      const messageTd = el('td', 'alert-detail', record.message || '');
      messageTd.title = record.message || '';
      row.append(timeTd, hostTd, sourceTd, categoryTd, severityTd, userTd, ipTd, messageTd);
      eventBody.append(row);
    }
  }
  syncMonitorSelection();
}

async function deleteMonitor(monitor) {
  if (!confirm('Delete monitor "' + monitor.name + '"? Its alert history is deleted too.')) return;
  try {
    await api('/api/v1/monitors/' + encodeURIComponent(monitor.id), { method: 'DELETE' });
    toast('Monitor deleted', 'ok');
    await loadAll();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function checkMonitorNow(monitor) {
  try {
    await api('/api/v1/monitors/' + encodeURIComponent(monitor.id) + '/check', { method: 'POST', body: '{}' });
    toast('Check requested for ' + monitor.name, 'ok');
    // The engine normally finishes cached checks quickly. Network probes may
    // take longer, so poll briefly instead of asking the operator to refresh.
    const before = monitor.last_checked_at || '';
    for (let attempt = 0; attempt < 12; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      await loadAll({ silent: true });
      const current = (state.monitors || []).find((entry) => entry.id === monitor.id);
      if (current && (current.last_checked_at || '') !== before) break;
    }
    await loadAll({ force: true });
  } catch (error) {
    toast(error.message, 'error');
  }
}

function monitorPayload(monitor, overrides = {}) {
  return {
    name: monitor.name,
    type: monitor.type,
    target: monitor.target || '',
    warning: Number(monitor.warning) || 0,
    critical: Number(monitor.critical) || 0,
    interval_seconds: Number(monitor.interval_seconds) || 300,
    repeat_minutes: Number(monitor.repeat_minutes) || 0,
    cooldown_minutes: Number(monitor.cooldown_minutes) || 0,
    recipients: monitor.recipients || '',
    enabled: Boolean(monitor.enabled),
    assignments: (monitor.assignments || []).map((assignment) => ({
      scope: assignment.scope,
      target: assignment.target || '',
    })),
    ...overrides,
  };
}

async function updateMonitorsBulk(monitors, overrides, successLabel) {
  if (!monitors.length) {
    toast('No monitors selected', 'error');
    return;
  }
  let updated = 0;
  const failures = [];
  for (const monitor of monitors) {
    try {
      await api('/api/v1/monitors/' + encodeURIComponent(monitor.id), {
        method: 'PUT',
        body: JSON.stringify(monitorPayload(monitor, overrides)),
      });
      updated++;
    } catch (error) {
      failures.push(monitor.name + ': ' + error.message);
    }
  }
  await loadAll({ force: true });
  if (failures.length) {
    const detail = failures.slice(0, 3).join('; ') + (failures.length > 3 ? '; …' : '');
    toast(updated + ' updated, ' + failures.length + ' failed — ' + detail, 'error');
  } else {
    toast((successLabel || 'Monitors updated') + (updated ? ' (' + updated + ')' : ''), 'ok');
  }
}

async function setSelectedMonitorsEnabled(enabled) {
  const monitors = selectedMonitors();
  if (!monitors.length) {
    toast('No monitors selected', 'error');
    return;
  }
  const action = enabled ? 'Enable' : 'Disable';
  if (!confirm(action + ' ' + monitors.length + ' selected monitor' + (monitors.length === 1 ? '' : 's') + '?')) return;
  await updateMonitorsBulk(monitors, { enabled }, action + 'd');
}

async function checkSelectedMonitors(monitors) {
  const enabled = monitors.filter((monitor) => monitor.enabled);
  if (!enabled.length) {
    toast('No enabled monitors selected', 'error');
    return;
  }
  const before = new Map(enabled.map((monitor) => [monitor.id, monitor.last_checked_at || '']));
  let requested = 0;
  const failures = [];
  for (const monitor of enabled) {
    try {
      await api('/api/v1/monitors/' + encodeURIComponent(monitor.id) + '/check', { method: 'POST', body: '{}' });
      requested++;
    } catch (error) {
      failures.push(monitor.name + ': ' + error.message);
    }
  }
  if (!requested) {
    toast('Check failed — ' + failures[0], 'error');
    return;
  }
  toast('Check requested for ' + requested + ' monitor' + (requested === 1 ? '' : 's'), 'ok');
  for (let attempt = 0; attempt < 12; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    await loadAll({ silent: true });
    const pending = enabled.filter((monitor) => {
      const current = (state.monitors || []).find((entry) => entry.id === monitor.id);
      return current && (current.last_checked_at || '') === before.get(monitor.id);
    });
    if (!pending.length) break;
  }
  await loadAll({ force: true });
  if (failures.length) {
    toast(requested + ' checks queued, ' + failures.length + ' failed — ' + failures[0], 'error');
  }
}

function optionalMonitorField(parent, labelText, placeholder, type = 'text') {
  const wrapper = el('label', 'field', labelText);
  const row = el('div', 'optional-input');
  const toggle = el('input');
  toggle.type = 'checkbox';
  const input = el('input');
  input.type = type;
  input.placeholder = placeholder || '';
  input.autocomplete = 'off';
  input.spellcheck = false;
  input.disabled = true;
  input.setAttribute('aria-label', labelText);
  toggle.addEventListener('change', () => {
    input.disabled = !toggle.checked;
    if (toggle.checked) input.focus();
  });
  row.append(toggle, input);
  wrapper.append(row);
  parent.append(wrapper);
  return { toggle, input };
}

function showMonitorBulkEditModal(monitors) {
  if (!monitors.length) {
    toast('No monitors selected', 'error');
    return;
  }
  const form = el('form', 'modal-body');
  form.append(el('p', 'muted', 'Only the fields you enable here are changed. Names, types, targets, thresholds, and assignments keep their current values.'));
  const enabledMode = selectField(form, 'Enabled', 'enabled_mode', [
    ['keep', 'No change'],
    ['enable', 'Enable'],
    ['disable', 'Disable'],
  ]);
  const scheduleRow = el('div', 'form-row three');
  const interval = optionalMonitorField(scheduleRow, 'Interval (seconds)', '300', 'number');
  const repeat = optionalMonitorField(scheduleRow, 'Repeat (minutes)', '60', 'number');
  const cooldown = optionalMonitorField(scheduleRow, 'Cooldown (minutes)', '15', 'number');
  form.append(scheduleRow);
  const recipients = optionalMonitorField(form, 'Alert recipients', 'ops@example.com, oncall@example.com');
  form.append(el('p', 'field-note', 'Leave a field unchecked to keep its current value. Checking recipients with a blank value clears the per-monitor override.'));
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const save = el('button', 'btn primary', 'Update ' + monitors.length + ' monitor' + (monitors.length === 1 ? '' : 's'));
  save.type = 'submit';
  actions.append(cancel, save);
  form.append(actions);
  const close = openModal('Update ' + monitors.length + ' selected monitor' + (monitors.length === 1 ? '' : 's'), form);
  cancel.addEventListener('click', close);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const overrides = {};
    if (enabledMode.value === 'enable') overrides.enabled = true;
    if (enabledMode.value === 'disable') overrides.enabled = false;
    if (interval.toggle.checked) {
      const value = Number(interval.input.value);
      if (!Number.isInteger(value) || value < 30 || value > 86400) {
        toast('Interval must be a whole number between 30 and 86400 seconds', 'error');
        return;
      }
      overrides.interval_seconds = value;
    }
    if (repeat.toggle.checked) {
      const value = Number(repeat.input.value);
      if (!Number.isInteger(value) || value < 0 || value > 10080) {
        toast('Repeat must be a whole number between 0 and 10080 minutes', 'error');
        return;
      }
      overrides.repeat_minutes = value;
    }
    if (cooldown.toggle.checked) {
      const value = Number(cooldown.input.value);
      if (!Number.isInteger(value) || value < 0 || value > 1440) {
        toast('Cooldown must be a whole number between 0 and 1440 minutes', 'error');
        return;
      }
      overrides.cooldown_minutes = value;
    }
    if (recipients.toggle.checked) overrides.recipients = recipients.input.value.trim();
    if (!Object.keys(overrides).length) {
      toast('Choose at least one field to update', 'error');
      return;
    }
    close();
    await updateMonitorsBulk(monitors, overrides, 'Monitors updated');
  });
}

function setFieldLabel(control, text) {
  const wrapper = control.closest('label.field');
  if (!wrapper) return;
  for (const node of wrapper.childNodes) {
    if (node.nodeType === Node.TEXT_NODE) {
      node.nodeValue = text;
      return;
    }
  }
}

function showMonitorModal(monitor = null, preset = null) {
  const editing = Boolean(monitor);
  const source = monitor || preset || {};
  const assignments = (source.assignments || []).map((assignment) => ({ scope: assignment.scope, target: assignment.target || '' }));
  const form = el('form', 'modal-body');
  form.append(el('p', 'muted', 'Monitors are evaluated by the controller. Host metrics and service state come from the collector; network checks are read-only probes.'));

  const topRow = el('div', 'form-row');
  const name = inputField(topRow, 'Name', 'name', 'Web servers — CPU');
  const type = selectField(topRow, 'Type', 'type', Object.entries(MONITOR_TYPES).map(([value, info]) => [value, info.label]));
  form.append(topRow);

  const targetWrap = el('label', 'field', 'Target');
  const target = el('input');
  target.name = 'target';
  target.type = 'text';
  target.autocomplete = 'off';
  target.spellcheck = false;
  targetWrap.append(target);
  form.append(targetWrap);

  const enabledWrap = el('label', 'field checkbox-field');
  const enabled = el('input');
  enabled.type = 'checkbox';
  enabled.checked = source.enabled !== false;
  enabledWrap.append(enabled, document.createTextNode('Enabled'));
  form.append(enabledWrap);

  const thresholdRow = el('div', 'form-row');
  const warning = inputField(thresholdRow, 'Warning', 'warning', '80', 'number');
  const critical = inputField(thresholdRow, 'Critical', 'critical', '90', 'number');
  warning.step = 'any';
  critical.step = 'any';
  form.append(thresholdRow);
  const thresholdNote = el('p', 'field-note');
  form.append(thresholdNote);

  const scheduleRow = el('div', 'form-row three');
  const interval = inputField(scheduleRow, 'Interval (seconds)', 'interval_seconds', '300', 'number');
  const repeat = inputField(scheduleRow, 'Repeat (minutes)', 'repeat_minutes', '60', 'number');
  const cooldown = inputField(scheduleRow, 'Cooldown (minutes)', 'cooldown_minutes', '15', 'number');
  form.append(scheduleRow);

  const recipients = inputField(form, 'Alert recipients (optional)', 'recipients', 'ops@example.com, oncall@example.com');
  recipients.spellcheck = false;
  form.append(el('p', 'field-note', 'Leave recipients blank to use the SMTP defaults. Repeat is the reminder interval while an alert stays active; cooldown suppresses repeat emails.'));

  const assignmentCard = el('div', 'detail-card');
  assignmentCard.append(el('h3', '', 'Assignments'));
  assignmentCard.append(el('p', 'muted', 'A monitor can target the whole fleet, a group, a tag, or one host. Add one or more assignments.'));
  const assignmentControls = el('div', 'form-row assignment-controls');
  const scope = selectField(assignmentControls, 'Scope', 'scope', [['fleet', 'Fleet'], ['host', 'Host'], ['group', 'Group'], ['tag', 'Tag']]);
  const assignmentTargetWrap = el('label', 'field', 'Target');
  const hostSelect = el('select');
  hostSelect.name = 'assignment_host';
  for (const hostEntry of state.hosts) {
    const option = el('option', '', hostEntry.name + ' (' + hostEntry.address + ')');
    option.value = hostEntry.id;
    hostSelect.append(option);
  }
  const textTarget = el('input');
  textTarget.name = 'assignment_target';
  textTarget.type = 'text';
  textTarget.autocomplete = 'off';
  textTarget.spellcheck = false;
  const fleetNote = el('div', 'field-static', 'All managed hosts');
  fleetNote.classList.add('hidden');
  const groupDatalist = el('datalist');
  groupDatalist.id = 'monitor-groups-' + Math.random().toString(36).slice(2, 8);
  for (const value of [...new Set(state.hosts.map((hostEntry) => hostEntry.group_name).filter(Boolean))]) {
    const option = el('option');
    option.value = value;
    groupDatalist.append(option);
  }
  const tagDatalist = el('datalist');
  tagDatalist.id = 'monitor-tags-' + Math.random().toString(36).slice(2, 8);
  for (const value of [...new Set(state.hosts.flatMap((hostEntry) => String(hostEntry.tags || '').split(',').map((tag) => tag.trim())).filter(Boolean))]) {
    const option = el('option');
    option.value = value;
    tagDatalist.append(option);
  }
  assignmentTargetWrap.append(hostSelect, textTarget, fleetNote);
  assignmentControls.append(assignmentTargetWrap);
  const addAssignment = el('button', 'btn', 'Add');
  addAssignment.type = 'button';
  assignmentControls.append(addAssignment);
  assignmentCard.append(assignmentControls, groupDatalist, tagDatalist);
  const chips = el('div', 'assignment-chips');
  assignmentCard.append(chips);
  form.append(assignmentCard);

  const standaloneNote = el('div', 'detail-card hidden');
  standaloneNote.append(
    el('h3', '', 'Standalone probe'),
    el('p', 'muted', 'Network checks run from the controller against the target above. They do not need a host assignment and keep working if the Docker host or SSH access is unavailable.'),
  );
  form.append(standaloneNote);

  const syncAssignmentTarget = () => {
    const value = scope.value;
    hostSelect.classList.toggle('hidden', value !== 'host');
    textTarget.classList.toggle('hidden', value === 'host' || value === 'fleet');
    fleetNote.classList.toggle('hidden', value !== 'fleet');
    if (value === 'group') {
      textTarget.placeholder = 'web-prod';
      textTarget.setAttribute('list', groupDatalist.id);
    } else if (value === 'tag') {
      textTarget.placeholder = 'prod';
      textTarget.setAttribute('list', tagDatalist.id);
    } else {
      textTarget.placeholder = '';
      textTarget.removeAttribute('list');
    }
    addAssignment.disabled = value === 'host' && state.hosts.length === 0;
  };
  const renderAssignments = () => {
    chips.replaceChildren();
    if (!assignments.length) {
      chips.append(el('span', 'muted', 'No assignments yet.'));
      return;
    }
    for (const assignment of assignments) {
      const chip = el('span', 'assignment-chip');
      chip.append(el('span', '', monitorAssignmentLabel(assignment)));
      const remove = el('button', 'chip-remove', '×');
      remove.type = 'button';
      remove.title = 'Remove assignment';
      remove.addEventListener('click', () => {
        const index = assignments.indexOf(assignment);
        if (index >= 0) assignments.splice(index, 1);
        renderAssignments();
      });
      chip.append(remove);
      chips.append(chip);
    }
  };
  addAssignment.addEventListener('click', () => {
    const selectedScope = scope.value;
    let value = selectedScope === 'host' ? hostSelect.value : textTarget.value.trim();
    if (selectedScope === 'fleet') value = '';
    if (selectedScope !== 'fleet' && !value) {
      toast('Choose a target for this assignment', 'error');
      return;
    }
    if (assignments.some((entry) => entry.scope === selectedScope && entry.target === value)) {
      toast('That assignment is already added', 'error');
      return;
    }
    assignments.push({ scope: selectedScope, target: value });
    textTarget.value = '';
    renderAssignments();
  });

  const applyMonitorType = (setDefaults) => {
    const info = MONITOR_TYPES[type.value] || {};
    const network = isNetworkMonitorType(type.value);
    targetWrap.classList.toggle('hidden', info.target === 'none');
    name.placeholder = info.namePlaceholder || 'Monitor name';
    if (info.targetLabel) setFieldLabel(target, info.targetLabel);
    target.placeholder = info.placeholder || '';
    thresholdRow.classList.toggle('hidden', info.threshold === 'none');
    thresholdNote.textContent = info.note || '';
    assignmentCard.classList.toggle('hidden', network);
    standaloneNote.classList.toggle('hidden', !network);
    if (network && assignments.length) {
      assignments.length = 0;
      renderAssignments();
    }
    if (info.threshold && info.threshold !== 'none') {
      setFieldLabel(warning, info.warningLabel || 'Warning');
      setFieldLabel(critical, info.criticalLabel || 'Critical');
    }
    if (setDefaults) {
      if (info.threshold && info.threshold !== 'none') {
        warning.value = String(info.warning ?? 0);
        critical.value = String(info.critical ?? 0);
      } else {
        warning.value = '0';
        critical.value = '0';
      }
      target.value = info.defaultTarget || '';
    }
  };

  name.value = source.name || '';
  type.value = source.type || 'host.cpu';
  target.value = source.target || '';
  const initialType = MONITOR_TYPES[type.value] || {};
  warning.value = source.warning !== undefined ? String(source.warning) : String(initialType.warning ?? 0);
  critical.value = source.critical !== undefined ? String(source.critical) : String(initialType.critical ?? 0);
  interval.value = String(source.interval_seconds || 300);
  repeat.value = String(source.repeat_minutes ?? 60);
  cooldown.value = String(source.cooldown_minutes ?? 15);
  recipients.value = source.recipients || '';
  applyMonitorType(false);
  syncAssignmentTarget();
  renderAssignments();
  type.addEventListener('change', () => applyMonitorType(true));
  scope.addEventListener('change', syncAssignmentTarget);

  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const webPreset = Boolean(preset) && isNetworkMonitorType(source.type);
  const save = el('button', 'btn primary', editing ? 'Save monitor' : webPreset ? 'Add web service' : 'Add monitor');
  save.type = 'submit';
  actions.append(cancel, save);
  form.append(actions);
  const close = openModal(editing ? 'Edit monitor — ' + monitor.name : webPreset ? 'Add web service monitor' : 'Add monitor', form, null, 'wide');
  cancel.addEventListener('click', close);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!assignments.length && !isNetworkMonitorType(type.value)) {
      toast('Add at least one assignment', 'error');
      return;
    }
    const payload = {
      name: name.value.trim(),
      type: type.value,
      target: target.value.trim(),
      warning: Number(warning.value || 0),
      critical: Number(critical.value || 0),
      interval_seconds: Number(interval.value || 300),
      repeat_minutes: Number(repeat.value || 0),
      cooldown_minutes: Number(cooldown.value || 0),
      recipients: recipients.value.trim(),
      enabled: enabled.checked,
      assignments,
    };
    try {
      const url = editing ? '/api/v1/monitors/' + encodeURIComponent(monitor.id) : '/api/v1/monitors';
      await api(url, { method: editing ? 'PUT' : 'POST', body: JSON.stringify(payload) });
      close();
      toast(editing ? 'Monitor updated' : 'Monitor added', 'ok');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

async function showSMTPModal() {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Alert email uses SMTP with TLS when authentication is configured. The password is stored only in the encrypted database and is never returned by the API.'));
  if (state.status.demo) {
    body.append(el('p', 'preview-warning', 'Demo mode: email delivery is simulated and nothing is sent. Do not enter real SMTP credentials or secrets.'));
  }
  const enabledWrap = el('label', 'field checkbox-field');
  const enabled = el('input');
  enabled.type = 'checkbox';
  enabledWrap.append(enabled, document.createTextNode('Enable email alerts'));
  body.append(enabledWrap);
  const grid = el('div', 'settings-grid');
  const host = inputField(grid, 'SMTP host', 'host', 'smtp.example.com');
  const port = inputField(grid, 'Port', 'port', '587', 'number');
  const mode = selectField(grid, 'Security', 'mode', [['starttls', 'STARTTLS (recommended)'], ['tls', 'Implicit TLS'], ['none', 'Plain text (no auth)']]);
  const username = inputField(grid, 'Username (optional)', 'username', 'alerts@example.com');
  body.append(grid);
  const password = inputField(body, 'SMTP password', 'password', 'Stored password — leave blank to keep', 'password');
  password.autocomplete = 'new-password';
  const clearWrap = el('label', 'field checkbox-field');
  const clearPassword = el('input');
  clearPassword.type = 'checkbox';
  clearWrap.append(clearPassword, document.createTextNode('Clear the stored password (also disables SMTP auth)'));
  body.append(clearWrap);
  const from = inputField(body, 'From address', 'from', 'hibp@example.com');
  const recipients = inputField(body, 'Default recipients', 'recipients', 'ops@example.com, oncall@example.com');
  recipients.spellcheck = false;
  const severityGrid = el('div', 'settings-grid');
  const warningRecipients = inputField(severityGrid, 'Warning recipients (optional)', 'warning_recipients', 'Defaults to the default recipients');
  const criticalRecipients = inputField(severityGrid, 'Critical recipients (optional)', 'critical_recipients', 'Defaults to the default recipients');
  const recoveryRecipients = inputField(severityGrid, 'Recovery recipients (optional)', 'recovery_recipients', 'Defaults to the default recipients');
  for (const field of [warningRecipients, criticalRecipients, recoveryRecipients]) field.spellcheck = false;
  body.append(severityGrid);
  const timeout = inputField(body, 'SMTP timeout (seconds)', 'timeout_seconds', '15', 'number');
  const testTo = inputField(body, 'Test recipient (optional)', 'test_to', 'Defaults to the recipient list');
  body.append(el('p', 'field-note', 'STARTTLS upgrades a plaintext connection before AUTH. Username and password are rejected over unencrypted SMTP. For a local Postfix relay, use its IP address, port 25, Plain text (no auth), and blank username/password. A test message is sent using the saved settings.'));
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const test = el('button', 'btn', 'Save and send test');
  test.type = 'button';
  const save = el('button', 'btn primary', 'Save');
  save.type = 'button';
  actions.append(cancel, test, save);
  body.append(actions);
  const close = openModal('Email notifications', body);
  cancel.addEventListener('click', close);

  const payload = () => ({
    enabled: enabled.checked,
    host: host.value.trim(),
    port: Number(port.value || 587),
    mode: mode.value,
    username: username.value.trim(),
    password: password.value,
    clear_password: clearPassword.checked,
    from: from.value.trim(),
    recipients: recipients.value.trim(),
    warning_recipients: warningRecipients.value.trim(),
    critical_recipients: criticalRecipients.value.trim(),
    recovery_recipients: recoveryRecipients.value.trim(),
    timeout_seconds: Number(timeout.value || 15),
  });
  const persist = async () => {
    const result = await api('/api/v1/notifications/smtp', { method: 'PUT', body: JSON.stringify(payload()) });
    password.value = '';
    clearPassword.checked = false;
    return result.smtp;
  };

  try {
    const data = await api('/api/v1/notifications/smtp');
    const smtp = data.smtp || {};
    enabled.checked = Boolean(smtp.enabled);
    host.value = smtp.host || '';
    port.value = String(smtp.port || 587);
    mode.value = smtp.mode || 'starttls';
    username.value = smtp.username || '';
    from.value = smtp.from || '';
    recipients.value = smtp.recipients || '';
    warningRecipients.value = smtp.warning_recipients || '';
    criticalRecipients.value = smtp.critical_recipients || '';
    recoveryRecipients.value = smtp.recovery_recipients || '';
    timeout.value = String(smtp.timeout_seconds || 15);
    if (smtp.password_set) {
      password.placeholder = 'Stored password — leave blank to keep';
      clearWrap.classList.remove('hidden');
    } else {
      clearWrap.classList.add('hidden');
    }
  } catch (error) {
    toast(error.message, 'error');
  }

  let clearedUsername = '';
  clearPassword.addEventListener('change', () => {
    if (clearPassword.checked) {
      clearedUsername = username.value;
      username.value = '';
      password.value = '';
      username.disabled = true;
      password.disabled = true;
    } else {
      if (!username.value) username.value = clearedUsername;
      username.disabled = false;
      password.disabled = false;
    }
  });

  save.addEventListener('click', async () => {
    try {
      await persist();
      close();
      toast('Email settings saved', 'ok');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  test.addEventListener('click', async () => {
    test.disabled = true;
    test.textContent = 'Sending…';
    try {
      await persist();
      const result = await api('/api/v1/notifications/smtp/test', {
        method: 'POST',
        body: JSON.stringify({ to: testTo.value.trim() }),
      });
      toast('Test email sent to ' + (result.recipients || []).join(', '), 'ok');
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      test.disabled = false;
      test.textContent = 'Save and send test';
    }
  });
}

function scheduleModeLabel(mode) {
  return mode === 'apply' ? 'apply' : 'check';
}

function scheduleStatusBadge(status) {
  const cls = status === 'success' ? 'green' : status === 'failed' ? 'red' : status === 'running' ? 'amber' : 'amber';
  return el('span', 'badge ' + cls, status || 'not run');
}

function formatRunDuration(run) {
  const started = new Date(run.started_at).getTime();
  const finished = new Date(run.finished_at).getTime();
  if (Number.isNaN(started) || Number.isNaN(finished)) return '—';
  const seconds = Math.max(0, Math.round((finished - started) / 1000));
  if (seconds < 60) return seconds + 's';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
  return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
}

function renderSchedules() {
  const body = $('schedule-body');
  if (!body) return;
  const schedules = state.schedules || [];
  const runs = state.runs || [];
  const enabled = schedules.filter((schedule) => schedule.enabled).length;
  const applying = schedules.filter((schedule) => schedule.mode === 'apply').length;
  $('schedule-summary').textContent = schedules.length + ' schedule' + (schedules.length === 1 ? '' : 's') + ' · ' + enabled + ' enabled · ' + applying + ' apply';
  body.replaceChildren();
  if (!schedules.length) {
    body.append(emptyTableRow(7, 'No patch schedules yet. Add a schedule to run checks or applies on a cron-like cadence.'));
  }
  for (const schedule of schedules) {
    const row = el('tr');
    const nameTd = el('td');
    nameTd.append(el('div', 'host-name', schedule.name));
    nameTd.append(el('div', 'host-ip', (schedule.enabled ? 'enabled' : 'disabled') + (schedule.run_if_missed ? ' · catch up' : '') + (schedule.retries ? ' · ' + schedule.retries + ' retries' : '') + (schedule.reboot_after_apply ? ' · reboot if required' : '')));
    const modeTd = el('td');
    modeTd.append(el('span', 'badge ' + (schedule.mode === 'apply' ? 'red' : 'amber'), scheduleModeLabel(schedule.mode)));
    const cronTd = el('td');
    cronTd.append(el('div', 'mono', schedule.cron));
    cronTd.append(el('div', 'host-ip', schedule.timezone || 'UTC'));
    const targetTd = el('td');
    const targetWrap = el('div', 'assignment-pills');
    for (const assignment of schedule.assignments || []) targetWrap.append(el('span', 'assignment-pill', monitorAssignmentLabel(assignment)));
    targetTd.append(targetWrap);
    const nextTd = el('td');
    if (schedule.next_run_at) {
      const next = el('span', 'nowrap', new Date(schedule.next_run_at).toLocaleString());
      next.title = schedule.next_run_at;
      nextTd.append(next);
      nextTd.append(el('div', 'muted', schedule.timezone || 'UTC'));
    } else {
      nextTd.append(el('span', 'muted', '—'));
    }
    const lastTd = el('td');
    const lastStatus = scheduleStatusBadge(schedule.last_status || '');
    if (schedule.last_summary) lastStatus.title = schedule.last_summary;
    lastTd.append(lastStatus);
    if (schedule.last_summary) lastTd.append(el('div', 'muted monitor-status-summary', schedule.last_summary));
    if (schedule.last_run_at) lastTd.append(el('div', 'muted', relativeTime(schedule.last_run_at)));
    const actionsTd = el('td');
    const actions = el('div', 'actions');
    const run = actionButton('Run now', () => runScheduleNow(schedule));
    run.disabled = !schedule.enabled;
    if (!schedule.enabled) run.title = 'Enable the schedule first';
    actions.append(run, actionButton('Edit', () => showScheduleModal(schedule)), actionButton('Delete', () => deleteSchedule(schedule), 'danger'));
    actionsTd.append(actions);
    row.append(nameTd, modeTd, cronTd, targetTd, nextTd, lastTd, actionsTd);
    body.append(row);
  }

  const runBody = $('schedule-run-body');
  runBody.replaceChildren();
  if (!runs.length) {
    runBody.append(emptyTableRow(8, 'No scheduled runs yet. Run-now results and scheduled patch attempts appear here.'));
  }
  const scheduleNames = new Map(schedules.map((schedule) => [schedule.id, schedule.name]));
  const hostNames = new Map(state.hosts.map((host) => [host.id, host.name]));
  for (const run of runs) {
    const row = el('tr');
    const timeTd = el('td');
    const time = el('span', 'nowrap', relativeTime(run.started_at));
    time.title = new Date(run.started_at).toLocaleString();
    timeTd.append(time);
    const scheduleTd = el('td', '', scheduleNames.get(run.schedule_id) || (run.schedule_id ? run.schedule_id.slice(0, 8) : 'manual'));
    const hostTd = el('td', '', hostNames.get(run.host_id) || (run.host_id ? run.host_id.slice(0, 8) : '—'));
    const actionTd = el('td', '', run.action === 'patch-apply' ? 'apply' : run.action === 'patch-check' ? 'check' : run.action);
    const statusTd = el('td');
    statusTd.append(scheduleStatusBadge(run.status));
    const exitTd = el('td', '', String(run.exit_code));
    const durationTd = el('td', '', run.status === 'running' ? 'running' : formatRunDuration(run));
    const outputTd = el('td', 'alert-detail', (run.error || run.output || '').replace(/\s+/g, ' ').slice(0, 180));
    outputTd.title = [run.error, run.output].filter(Boolean).join('\n');
    row.append(timeTd, scheduleTd, hostTd, actionTd, statusTd, exitTd, durationTd, outputTd);
    runBody.append(row);
  }
}

async function runScheduleNow(schedule) {
  if (!confirm('Run schedule "' + schedule.name + '" now? This runs the configured check or apply immediately.')) return;
  beginOperation('Queued schedule — ' + schedule.name, 'The scheduler will start the next run.');
  try {
    await api('/api/v1/schedules/' + encodeURIComponent(schedule.id) + '/run', { method: 'POST', body: '{}' });
    toast('Schedule queued: ' + schedule.name, 'ok');
    await new Promise((resolve) => setTimeout(resolve, 1500));
    finishOperation('Schedule started — ' + schedule.name, 'Live run status will appear above.');
    await loadAll({ force: true });
  } catch (error) {
    finishOperation('Schedule failed — ' + schedule.name, error.message, true);
    toast(error.message, 'error');
  }
}

async function deleteSchedule(schedule) {
  if (!confirm('Delete schedule "' + schedule.name + '"? Existing run history is retained.')) return;
  try {
    await api('/api/v1/schedules/' + encodeURIComponent(schedule.id), { method: 'DELETE' });
    toast('Schedule deleted', 'ok');
    await loadAll();
  } catch (error) {
    toast(error.message, 'error');
  }
}

function showScheduleModal(schedule = null) {
  const editing = Boolean(schedule);
  const source = schedule || {};
  const form = el('form', 'modal-body');
  form.append(el('p', 'muted', 'Schedules use a standard five-field cron expression in the selected IANA timezone. The host must use key authentication and the restricted NOPASSWD helper; scheduled jobs never prompt for credentials.'));
  const topRow = el('div', 'form-row');
  const name = inputField(topRow, 'Name', 'name', 'Nightly patches');
  const mode = selectField(topRow, 'Mode', 'mode', [['check', 'Check only (dry run)'], ['apply', 'Apply updates']]);
  form.append(topRow);
  const enabledWrap = el('label', 'field checkbox-field');
  const enabled = el('input');
  enabled.type = 'checkbox';
  enabled.checked = source.enabled !== false;
  enabledWrap.append(enabled, document.createTextNode('Enabled'));
  form.append(enabledWrap);
  const presetRow = el('div', 'form-row');
  const preset = selectField(presetRow, 'Cron preset', 'cron_preset', [
    ['custom', 'Custom expression'],
    ['0 3 * * *', 'Daily at 03:00'],
    ['0 3 * * 0', 'Weekly Sunday at 03:00'],
    ['0 */6 * * *', 'Every 6 hours'],
    ['0 3 1 * *', 'Monthly, first day at 03:00'],
  ]);
  const cron = inputField(presetRow, 'Cron expression', 'cron', '0 3 * * *');
  form.append(presetRow);
  const timingRow = el('div', 'form-row three');
  const timezone = inputField(timingRow, 'Timezone', 'timezone', 'UTC');
  const windowMinutes = inputField(timingRow, 'Late-start window (min)', 'window_minutes', '120', 'number');
  const jitter = inputField(timingRow, 'Jitter (seconds)', 'jitter_seconds', '60', 'number');
  form.append(timingRow);
  const limitsRow = el('div', 'form-row three');
  const concurrency = inputField(limitsRow, 'Max concurrency', 'max_concurrency', '3', 'number');
  const retries = inputField(limitsRow, 'Retries per host', 'retries', '0', 'number');
  const notify = selectField(limitsRow, 'Email', 'notify', [['failures', 'On failures'], ['always', 'Every run'], ['never', 'Never']]);
  const runIfMissed = el('label', 'field checkbox-field');
  const missed = el('input');
  missed.type = 'checkbox';
  runIfMissed.append(missed, document.createTextNode('Run the latest missed occurrence'));
  const rebootAfterApply = el('label', 'field checkbox-field');
  const rebootCheck = el('input');
  rebootCheck.type = 'checkbox';
  rebootAfterApply.append(rebootCheck, document.createTextNode('Reboot if required after a successful apply'));
  form.append(limitsRow);
  form.append(runIfMissed, rebootAfterApply);
  const recipients = inputField(form, 'Alert recipients (optional)', 'recipients', 'ops@example.com');
  recipients.spellcheck = false;
  const modeNote = el('p', 'field-note');
  form.append(modeNote);
  const syncModeNote = () => {
    rebootCheck.disabled = mode.value !== 'apply';
    if (mode.value !== 'apply') rebootCheck.checked = false;
    if (mode.value === 'apply') {
      modeNote.textContent = rebootCheck.checked
        ? 'Apply mode runs the target package manager as root. When enabled, HIBP asks the fixed helper for reboot state and reboots only when the target reports a reboot is required. Use a canary schedule first.'
        : 'Apply mode runs the target package manager as root on every eligible host. Reboots are not automatic unless enabled below. Use a canary schedule first.';
    } else {
      modeNote.textContent = 'Check mode is a dry run using the target package manager. It records the result but does not install updates.';
    }
  };
  mode.addEventListener('change', syncModeNote);
  rebootCheck.addEventListener('change', syncModeNote);
  syncModeNote();
  preset.addEventListener('change', () => {
    if (preset.value !== 'custom') cron.value = preset.value;
  });

  const assignmentCard = el('div', 'detail-card');
  assignmentCard.append(el('h3', '', 'Assignments'));
  assignmentCard.append(el('p', 'muted', 'Targets can be the fleet, a group, a tag, or individual hosts. Hosts without key auth or a trusted host key are skipped.'));
  const assignmentControls = el('div', 'form-row assignment-controls');
  const scope = selectField(assignmentControls, 'Scope', 'scope', [['fleet', 'Fleet'], ['host', 'Host'], ['group', 'Group'], ['tag', 'Tag']]);
  const assignmentTargetWrap = el('label', 'field', 'Target');
  const hostSelect = el('select');
  for (const hostEntry of state.hosts) {
    const option = el('option', '', hostEntry.name + ' (' + hostEntry.address + ')');
    option.value = hostEntry.id;
    hostSelect.append(option);
  }
  const textTarget = el('input');
  textTarget.type = 'text';
  textTarget.autocomplete = 'off';
  const fleetNote = el('div', 'field-static', 'All managed hosts');
  const groupDatalist = el('datalist');
  groupDatalist.id = 'schedule-groups-' + Math.random().toString(36).slice(2, 8);
  for (const value of [...new Set(state.hosts.map((hostEntry) => hostEntry.group_name).filter(Boolean))]) {
    const option = el('option');
    option.value = value;
    groupDatalist.append(option);
  }
  const tagDatalist = el('datalist');
  tagDatalist.id = 'schedule-tags-' + Math.random().toString(36).slice(2, 8);
  for (const value of [...new Set(state.hosts.flatMap((hostEntry) => String(hostEntry.tags || '').split(',').map((tag) => tag.trim())).filter(Boolean))]) {
    const option = el('option');
    option.value = value;
    tagDatalist.append(option);
  }
  assignmentTargetWrap.append(hostSelect, textTarget, fleetNote);
  assignmentControls.append(assignmentTargetWrap);
  const addAssignment = el('button', 'btn', 'Add');
  addAssignment.type = 'button';
  assignmentControls.append(addAssignment);
  assignmentCard.append(assignmentControls, groupDatalist, tagDatalist);
  const chips = el('div', 'assignment-chips');
  assignmentCard.append(chips);
  form.append(assignmentCard);
  const assignments = (source.assignments || []).map((assignment) => ({ scope: assignment.scope, target: assignment.target || '' }));

  const syncAssignmentTarget = () => {
    const value = scope.value;
    hostSelect.classList.toggle('hidden', value !== 'host');
    textTarget.classList.toggle('hidden', value === 'host' || value === 'fleet');
    fleetNote.classList.toggle('hidden', value !== 'fleet');
    if (value === 'group') {
      textTarget.placeholder = 'web-prod';
      textTarget.setAttribute('list', groupDatalist.id);
    } else if (value === 'tag') {
      textTarget.placeholder = 'prod';
      textTarget.setAttribute('list', tagDatalist.id);
    } else {
      textTarget.placeholder = '';
      textTarget.removeAttribute('list');
    }
    addAssignment.disabled = value === 'host' && state.hosts.length === 0;
  };
  const renderAssignments = () => {
    chips.replaceChildren();
    if (!assignments.length) {
      chips.append(el('span', 'muted', 'No assignments yet.'));
      return;
    }
    for (const assignment of assignments) {
      const chip = el('span', 'assignment-chip');
      chip.append(el('span', '', monitorAssignmentLabel(assignment)));
      const remove = el('button', 'chip-remove', '×');
      remove.type = 'button';
      remove.addEventListener('click', () => {
        const index = assignments.indexOf(assignment);
        if (index >= 0) assignments.splice(index, 1);
        renderAssignments();
      });
      chip.append(remove);
      chips.append(chip);
    }
  };
  addAssignment.addEventListener('click', () => {
    const selectedScope = scope.value;
    let value = selectedScope === 'host' ? hostSelect.value : textTarget.value.trim();
    if (selectedScope === 'fleet') value = '';
    if (selectedScope !== 'fleet' && !value) {
      toast('Choose a target for this assignment', 'error');
      return;
    }
    if (assignments.some((entry) => entry.scope === selectedScope && entry.target === value)) {
      toast('That assignment is already added', 'error');
      return;
    }
    assignments.push({ scope: selectedScope, target: value });
    textTarget.value = '';
    renderAssignments();
  });

  name.value = source.name || '';
  mode.value = source.mode || 'check';
  cron.value = source.cron || '0 3 * * *';
  timezone.value = source.timezone || 'UTC';
  windowMinutes.value = String(source.window_minutes || 120);
  jitter.value = String(source.jitter_seconds ?? 60);
  concurrency.value = String(source.max_concurrency || 3);
  retries.value = String(source.retries ?? 0);
  notify.value = source.notify || 'failures';
  recipients.value = source.recipients || '';
  missed.checked = Boolean(source.run_if_missed);
  rebootCheck.checked = Boolean(source.reboot_after_apply);
  preset.value = 'custom';
  syncModeNote();
  syncAssignmentTarget();
  renderAssignments();
  scope.addEventListener('change', syncAssignmentTarget);

  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const save = el('button', 'btn primary', editing ? 'Save schedule' : 'Add schedule');
  save.type = 'submit';
  actions.append(cancel, save);
  form.append(actions);
  const close = openModal(editing ? 'Edit schedule — ' + schedule.name : 'Add patch schedule', form, null, 'wide');
  cancel.addEventListener('click', close);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!assignments.length) {
      toast('Add at least one assignment', 'error');
      return;
    }
    const payload = {
      name: name.value.trim(), mode: mode.value, enabled: enabled.checked,
      cron: cron.value.trim(), timezone: timezone.value.trim(),
      window_minutes: Number(windowMinutes.value || 120),
      jitter_seconds: Number(jitter.value || 0),
      max_concurrency: Number(concurrency.value || 3),
      retries: Number(retries.value || 0),
      run_if_missed: missed.checked, reboot_after_apply: rebootCheck.checked,
      notify: notify.value, recipients: recipients.value.trim(), assignments,
    };
    try {
      const url = editing ? '/api/v1/schedules/' + encodeURIComponent(schedule.id) : '/api/v1/schedules';
      await api(url, { method: editing ? 'PUT' : 'POST', body: JSON.stringify(payload) });
      close();
      toast(editing ? 'Schedule updated' : 'Schedule added', 'ok');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

function showMonitorPreset(preset) {
  const target = String(preset.target || '');
  const assignment = (preset.assignments || []).find((entry) => entry.scope === 'host');
  const duplicate = state.monitors.some((monitor) => monitor.type === preset.type
    && String(monitor.target || '') === target
    && (!assignment || (monitor.assignments || []).some((entry) => entry.scope === 'host' && entry.target === assignment.target)));
  if (duplicate) {
    toast('A monitor already exists for this target', 'error');
    return;
  }
  showMonitorModal(null, preset);
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

function askPassword(title, message, options = {}) {
  return new Promise((resolve) => {
    const body = el('div', 'modal-body');
    body.append(el('p', 'muted', message));
    const wrapper = el('label', 'field', 'Password');
    const field = el('div', 'password-field');
    const input = el('input');
    input.type = 'password';
    input.autocomplete = 'off';
    input.autocapitalize = 'off';
    input.autocorrect = 'off';
    input.spellcheck = false;
    const mask = el('span', 'password-mask');
    mask.setAttribute('aria-hidden', 'true');
    const syncMask = () => { mask.textContent = '*'.repeat(Array.from(input.value).length); };
    for (const eventName of ['input', 'change', 'keyup', 'focus']) {
      input.addEventListener(eventName, syncMask);
    }
    field.append(input, mask);
    wrapper.append(field);
    body.append(wrapper);

    const actions = el('div', 'modal-actions');
    const cancel = el('button', 'btn', 'Cancel');
    cancel.type = 'button';
    const submit = el('button', 'btn primary', 'Continue');
    submit.type = 'button';
    actions.append(cancel, submit);
    body.append(actions);

    let settled = false;
    let submitting = false;
    const resolveOnce = (value) => {
      if (settled) return;
      settled = true;
      input.value = '';
      syncMask();
      resolve(value);
    };
    const close = openModal(title, body, () => {
      if (!submitting) resolveOnce(null);
    });
    const finish = () => {
      const value = input.value;
      if (!value && !options.allowEmpty) {
        input.focus();
        return;
      }
      submitting = true;
      close();
      resolveOnce(value);
    };
    cancel.addEventListener('click', close);
    submit.addEventListener('click', finish);
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        finish();
      }
    });
    setTimeout(() => { input.focus(); syncMask(); }, 0);
  });
}

async function passwordFor(host) {
  if (host.auth_type !== 'password') return '';
  if (state.passwords.has(host.id)) return state.passwords.get(host.id);
  const value = await askPassword('SSH password — ' + host.name, 'Used for this connection only. It is not stored. Characters are shown as *.');
  if (value === null) throw new Error('cancelled');
  state.passwords.set(host.id, value);
  return value;
}

async function sudoPasswordFor(host) {
  if (state.sudoPasswords.has(host.id)) return state.sudoPasswords.get(host.id);
  if (state.sharedSudoPassword && state.sharedSudoUsername === host.username) {
    return state.sharedSudoPassword;
  }
  const value = await askPassword(
    'sudo password — ' + host.name,
    'Reused in browser memory for hosts with the same SSH username until the tab closes. It is not stored. Characters are shown as *.',
  );
  if (value === null) throw new Error('cancelled');
  state.sudoPasswords.set(host.id, value);
  state.sharedSudoPassword = value;
  state.sharedSudoUsername = host.username;
  return value;
}

async function requestWithSudo(host, path, payloadFor, options = {}, sudoCache = null) {
  const request = (sudoPassword) => api(path, {
    ...options,
    body: JSON.stringify(payloadFor(sudoPassword)),
  });
  const remember = (value) => {
    if (!value) return;
    state.sudoPasswords.set(host.id, value);
    state.sharedSudoPassword = value;
    state.sharedSudoUsername = host.username;
  };
  const forget = () => {
    state.sudoPasswords.delete(host.id);
    if (state.sharedSudoUsername === host.username) {
      state.sharedSudoPassword = '';
      state.sharedSudoUsername = '';
    }
    if (sudoCache) sudoCache.value = '';
  };
  const askForSudo = async () => {
    let sudoPassword = sudoCache && sudoCache.value ? sudoCache.value : '';
    if (!sudoPassword) {
      sudoPassword = await sudoPasswordFor(host);
      if (sudoCache) sudoCache.value = sudoPassword;
    }
    remember(sudoPassword);
    return sudoPassword;
  };
  try {
    const cachedSudo = (sudoCache && sudoCache.value)
      || state.sudoPasswords.get(host.id)
      || (state.sharedSudoUsername === host.username ? state.sharedSudoPassword : '')
      || '';
    const result = await request(cachedSudo);
    remember(cachedSudo);
    return result;
  } catch (error) {
    if (error.status === 409 && error.data && error.data.code === 'sudo_password_required') {
      return request(await askForSudo());
    }
    if (error.status === 400 && error.data && error.data.code === 'sudo_password_invalid') {
      const rejected = (sudoCache && sudoCache.value)
        || state.sudoPasswords.get(host.id)
        || (state.sharedSudoUsername === host.username ? state.sharedSudoPassword : '')
        || '';
      forget();
      // A shared password from another host may be wrong for this one. Discard
      // it and prompt once, rather than failing the host with no way to continue.
      if (rejected) {
        return request(await askForSudo());
      }
    }
    throw error;
  }
}

async function testHost(host) {
  try {
    const password = await passwordFor(host);
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

async function deleteHost(host) {
  const ok = confirm('Delete host "' + host.name + '"? This permanently removes its facts, metrics, Docker inventory, trusted host key, and run history. The helper and sudoers rule on the target are not removed. This cannot be undone.');
  if (!ok) return;
  try {
    await api('/api/v1/hosts/' + encodeURIComponent(host.id), { method: 'DELETE' });
    state.selectedHosts.delete(host.id);
    state.passwords.delete(host.id);
    state.sudoPasswords.delete(host.id);
    toast('Host deleted: ' + host.name, 'ok');
    await loadAll();
  } catch (error) {
    toast(error.message, 'error');
  }
}

function showTrustModal(host, key, password) {
  const changed = key.kind === 'changed';
  const jump = key.scope === 'jump';
  const label = jump ? 'jump host' : 'host';
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', changed
    ? 'The ' + label + ' presented a different key than the one currently trusted. This can indicate a rebuild or a man-in-the-middle attack. Verify the new fingerprint through an independent channel before replacing the trusted key.'
    : 'Verify this ' + label + ' fingerprint through an independent channel before trusting it.'));
  const box = el('div', 'key-box');
  box.append(el('div', '', 'Presented: ' + key.key_type + ' ' + key.fingerprint));
  if (changed) {
    box.append(el('div', '', 'Previously trusted: ' + (key.expected_type || '—') + ' ' + (key.expected_fingerprint || '—')));
  }
  body.append(box);
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const trust = el('button', 'btn primary', changed ? 'Replace trusted key' : 'Trust this key');
  trust.type = 'button';
  actions.append(cancel, trust);
  body.append(actions);
  const title = changed
    ? (jump ? 'Jump host key changed — ' : 'Host key changed — ')
    : (jump ? 'Unknown jump host key — ' : 'Unknown host key — ');
  const close = openModal(title + host.name, body);
  cancel.addEventListener('click', close);
  trust.addEventListener('click', async () => {
    try {
      await api('/api/v1/hosts/' + encodeURIComponent(host.id) + (jump ? '/trust-jump-key' : '/trust-key'), {
        method: 'POST',
        body: JSON.stringify({ key_type: key.key_type, fingerprint: key.fingerprint, password }),
      });
      close();
      toast(changed ? 'Trusted the replacement ' + label + ' key. Testing connection…' : 'Trusted the ' + label + ' key. Testing connection…', 'ok');
      await testHost(host);
    } catch (error) {
      if (error.status === 409 && error.data && error.data.key) {
        close();
        showTrustModal(host, error.data.key, password);
        return;
      }
      toast(error.message, 'error');
    }
  });
}

async function bootstrapHost(host) {
  if (!confirm('Install the HIBP helper and restricted sudo rule on ' + host.name + '?')) return;
  toast('Installing helper on ' + host.name + '…');
  try {
    const password = await passwordFor(host);
    const result = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/bootstrap',
      (sudoPassword) => ({ password, sudo_password: sudoPassword }),
      { method: 'POST' },
    );
    showOutputModal('Helper installed — ' + host.name, {
      action: 'bootstrap',
      ok: true,
      exit_code: 0,
      output: result.output,
    });
    await loadAll();
  } catch (error) {
    if (error.status === 409 && error.data && error.data.code === 'host_key_untrusted') {
      toast('Trust the host key first; starting the connection test.', 'error');
      await testHost(host);
      return;
    }
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

async function showRunbookModal(hosts) {
  const targets = (Array.isArray(hosts) ? hosts.slice() : []);
  if (!targets.length) {
    toast('Select at least one host', 'error');
    return;
  }
  const body = el('form', 'modal-body');
  body.append(el('p', 'muted', 'Runbooks are typed, allowlisted actions. The controller validates parameters again before the helper executes them. Package actions have separate preview and apply steps. Checkmk registration answers the certificate prompt with y.'));
  const action = selectField(body, 'Action', 'runbook_action', [
    ['service-restart', 'Restart service'],
    ['service-enable', 'Enable service'],
    ['service-disable', 'Disable service'],
    ['package-remove-preview', 'Preview package removal'],
    ['package-remove-apply', 'Remove package'],
    ['package-install-preview', 'Preview repository package install'],
    ['package-install-apply', 'Install repository package'],
    ['checkmk-register', 'Register with Checkmk (Linux)'],
  ]);
  const parameter = inputField(body, 'Service unit', 'runbook_parameter', 'nginx.service');
  const note = el('p', 'field-note', 'Service actions require one systemd unit. Package actions accept comma-separated package names. Checkmk registration runs cmk-agent-ctl as root and answers y to the certificate prompt; the hostname must match Checkmk Setup, and blank uses the target local hostname. The registration password is kept only in controller memory.');
  body.append(note);

  const checkmkFields = el('div');
  checkmkFields.style.display = 'none';
  const checkmkRow = el('div', 'form-row');
  const checkmkHostname = inputField(checkmkRow, 'Target hostname', 'checkmk_hostname', 'blank = target local hostname');
  const checkmkServer = inputField(checkmkRow, 'Checkmk server', 'checkmk_server', 'checkmk:8000');
  const checkmkRow2 = el('div', 'form-row three');
  const checkmkSite = inputField(checkmkRow2, 'Site', 'checkmk_site', 'Bergling');
  const checkmkUser = inputField(checkmkRow2, 'User', 'checkmk_user', 'cmkadmin');
  const checkmkPassword = inputField(checkmkRow2, 'Password', 'checkmk_password', 'registration password', 'password');
  const checkmkPreviewLabel = el('p', 'field-note', 'Command preview (runs as root; password redacted):');
  const checkmkPreview = el('pre', 'key-box');
  checkmkPreview.style.whiteSpace = 'pre-wrap';
  checkmkPreview.style.margin = '0';
  const updateCheckmkPreview = () => {
    const hostname = checkmkHostname.value.trim() || '<target local hostname>';
    const server = checkmkServer.value.trim() || '<checkmk server>';
    const site = checkmkSite.value.trim() || '<site>';
    const user = checkmkUser.value.trim() || '<user>';
    checkmkPreview.textContent = 'cmk-agent-ctl register --hostname ' + hostname +
      ' --server ' + server + ' --site ' + site + ' --user ' + user + ' --password ********';
  };
  for (const field of [checkmkHostname, checkmkServer, checkmkSite, checkmkUser, checkmkPassword]) {
    field.addEventListener('input', updateCheckmkPreview);
  }
  updateCheckmkPreview();
  checkmkFields.append(checkmkRow, checkmkRow2, checkmkPreviewLabel, checkmkPreview);
  body.append(checkmkFields);

  const parameterField = parameter.closest('label.field');
  const sync = () => {
    const checkmk = action.value === 'checkmk-register';
    const pkg = action.value.startsWith('package-');
    if (parameterField) parameterField.style.display = checkmk ? 'none' : '';
    checkmkFields.style.display = checkmk ? '' : 'none';
    setFieldLabel(parameter, pkg ? 'Package names' : 'Service unit');
    parameter.placeholder = pkg ? 'checkmk-agent, checkmk-agent-plugins' : 'nginx.service';
  };
  action.addEventListener('change', sync);
  sync();
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const save = el('button', 'btn primary', 'Queue runbook');
  save.type = 'submit';
  actions.append(cancel, save);
  body.append(actions);
  const close = openModal('Runbook — ' + targets.length + ' host' + (targets.length === 1 ? '' : 's'), body);
  cancel.addEventListener('click', close);
  body.addEventListener('submit', async (event) => {
    event.preventDefault();
    let runbook;
    let confirm;
    if (action.value === 'checkmk-register') {
      const server = checkmkServer.value.trim();
      const site = checkmkSite.value.trim();
      const user = checkmkUser.value.trim();
      const password = checkmkPassword.value;
      if (!server || !site || !user || !password) {
        toast('Enter the Checkmk server, site, user, and password', 'error');
        return;
      }
      runbook = {
        action: 'checkmk-register',
        checkmk: {
          hostname: checkmkHostname.value.trim(),
          server,
          site,
          user,
          password,
        },
      };
      confirm = 'register';
    } else {
      const value = parameter.value.trim();
      if (!value) {
        toast('Enter a service unit or package name', 'error');
        return;
      }
      runbook = { action: action.value };
      confirm = 'run';
      if (action.value.startsWith('service-')) {
        runbook.unit = value;
      } else {
        runbook.packages = [...new Set(value.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean))];
        if (!runbook.packages.length) {
          toast('Enter at least one package name', 'error');
          return;
        }
        confirm = action.value.endsWith('-preview') ? 'preview' : action.value.startsWith('package-remove') ? 'remove' : 'install';
      }
    }
    const usernames = new Set(targets.map((host) => host.username));
    let sudoPassword = '';
    if (usernames.size === 1 && state.sharedSudoPassword && state.sharedSudoUsername === targets[0].username) {
      sudoPassword = state.sharedSudoPassword;
    } else {
      const entered = await askPassword(
        'Shared sudo password — runbook',
        'Used for every selected host in this runbook. Leave blank for passwordless sudo. Characters are shown as *.',
        { allowEmpty: true },
      );
      if (entered === null) return;
      sudoPassword = entered;
      if (entered && usernames.size === 1) {
        state.sharedSudoPassword = entered;
        state.sharedSudoUsername = targets[0].username;
      }
    }
    if (action.value === 'checkmk-register') checkmkPassword.value = '';
    close();
    await createJob('runbook', targets, { confirm, runbook, sudo_password: sudoPassword });
  });
}

async function fleetUpdateHelpers(hosts = null) {  const targets = (Array.isArray(hosts) ? hosts.slice() : state.hosts.slice());
  if (!targets.length) {
    toast(hosts ? 'No hosts selected' : 'No hosts to update', 'error');
    return;
  }
  const scope = hosts
    ? (targets.length === 1 ? 'the selected host' : 'the ' + targets.length + ' selected hosts')
    : ('all ' + targets.length + ' hosts');
  if (!confirm('Set up or update the HIBP helper on ' + scope + '?\n\nThis creates a durable background job. It uploads the running controller binary and rewrites the sudoers rule. You can provide one shared sudo password in the next step; leave it blank for passwordless sudo. The password is kept only in controller memory, never stored, and is lost if the controller restarts before the job finishes. Hosts that still need a password are then skipped; use the per-host Setup action in that case.')) {
    return;
  }
  const usernames = new Set(targets.map((host) => host.username));
  const value = await askPassword(
    'Shared sudo password — ' + targets.length + ' host' + (targets.length === 1 ? '' : 's'),
    'Used for every selected host in this job. It is not stored in the database. Leave blank for passwordless sudo. Characters are shown as *.',
    { allowEmpty: true },
  );
  if (value === null) return;
  if (value && usernames.size === 1) {
    state.sharedSudoPassword = value;
    state.sharedSudoUsername = targets[0].username;
  }
  await createJob('helper-setup', targets, { confirm: 'setup', sudo_password: value });
}

async function collectFacts(host) {
  if (hostCanUseJobs(host)) {
    await createJob('facts', [host]);
    return;
  }
  await collectFactsInteractive(host);
}

function hostCanUseJobs(host) {
  return Boolean(host && host.auth_type === 'key' && host.trusted_key);
}

async function collectFactsInteractive(host) {
  toast('Collecting facts from ' + host.name + '…');
  beginOperation('Collecting facts — ' + host.name, 'Running the fixed helper…');
  try {
    const password = await passwordFor(host);
    await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/facts',
      (sudoPassword) => ({ password, sudo_password: sudoPassword }),
      { method: 'POST' },
    );
    toast('Facts collected from ' + host.name, 'ok');
    finishOperation('Facts collected — ' + host.name, 'Host state refreshed.');
    await loadAll({ force: true });
  } catch (error) {
    finishOperation('Facts failed — ' + host.name, error.message, true);
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

async function fleetCollectFacts(hosts) {
  const targets = hosts.slice();
  if (!targets.length) {
    toast('Select at least one host', 'error');
    return;
  }
  if (!confirm('Collect facts from ' + targets.length + ' selected host(s) as a durable background job?')) return;
  await createJob('facts', targets);
}

function previewCounts(preview) {
  const counts = (preview && preview.counts) || {};
  return {
    upgrade: Number(counts.upgrade || 0),
    install: Number(counts.install || 0),
    remove: Number(counts.remove || 0),
    downgrade: Number(counts.downgrade || 0),
    reinstall: Number(counts.reinstall || 0),
  };
}

function previewTotal(preview) {
  const counts = previewCounts(preview);
  return counts.upgrade + counts.install + counts.remove + counts.downgrade + counts.reinstall;
}

function previewChips(preview) {
  const counts = previewCounts(preview);
  const wrap = el('div', 'preview-summary');
  const add = (label, value, cls) => {
    const chip = el('span', 'preview-count ' + cls);
    chip.append(document.createTextNode(label + ' '), el('b', '', String(value)));
    wrap.append(chip);
  };
  add('Upgrade', counts.upgrade, 'upgrade');
  add('Install', counts.install, 'install');
  add('Remove', counts.remove, 'remove');
  if (counts.downgrade) add('Downgrade', counts.downgrade, 'upgrade');
  if (counts.reinstall) add('Reinstall', counts.reinstall, 'install');
  return wrap;
}

function appendPreviewGroup(parent, title, action, changes) {
  if (!changes.length) return;
  const group = el('div', 'preview-group');
  const head = el('div', 'preview-group-head');
  head.append(document.createTextNode(title), el('span', 'badge ' + (action === 'remove' ? 'red' : action === 'upgrade' || action === 'downgrade' ? 'amber' : 'green'), String(changes.length)));
  group.append(head);
  const table = el('table', 'preview-table');
  const header = el('tr');
  header.append(el('th', '', 'Package'));
  if (action === 'remove') {
    header.append(el('th', '', 'Current version'));
  } else if (action === 'upgrade' || action === 'downgrade') {
    header.append(el('th', '', 'From'), el('th', '', 'To'));
  } else {
    header.append(el('th', '', 'Version'), el('th', '', 'Repository'));
  }
  table.append(header);
  for (const change of changes) {
    const row = el('tr');
    row.append(el('td', '', change.name));
    if (action === 'remove') {
      row.append(el('td', 'version remove-version', change.old_version || '—'));
    } else if (action === 'upgrade' || action === 'downgrade') {
      row.append(
        el('td', 'version', change.old_version || '—'),
        el('td', 'version new-version', change.new_version || '—'),
      );
    } else {
      row.append(
        el('td', 'version', change.new_version || '—'),
        el('td', 'version', change.repository || '—'),
      );
    }
    table.append(row);
  }
  group.append(table);
  parent.append(group);
}

function renderPackagePreview(container, preview) {
  container.replaceChildren();
  container.append(previewChips(preview));
  const packages = preview.packages || [];
  const groups = [
    ['Upgrades', 'upgrade'],
    ['Downgrades', 'downgrade'],
    ['Installs', 'install'],
    ['Removals', 'remove'],
    ['Reinstalls', 'reinstall'],
  ];
  for (const [label, action] of groups) {
    appendPreviewGroup(container, label, action, packages.filter((change) => change.action === action));
  }
  if (!packages.length) {
    container.append(el('div', 'preview-empty', 'No package changes detected. Nothing to apply.'));
  }
  for (const warning of preview.warnings || []) {
    container.append(el('p', 'preview-warning', warning));
  }
  if (preview.output) {
    const raw = el('details', 'preview-raw');
    raw.append(el('summary', '', 'Raw package-manager output'));
    raw.append(el('pre', '', preview.output));
    container.append(raw);
  }
}

async function fetchPatchPreview(host, sharedSudo = null) {
  const password = await passwordFor(host);
  return requestWithSudo(
    host,
    '/api/v1/hosts/' + encodeURIComponent(host.id) + '/patch/preview',
    (sudoPassword) => ({ password, sudo_password: sudoPassword }),
    { method: 'POST' },
    sharedSudo,
  );
}

function showPreviewDetailsModal(host, preview) {
  const body = el('div', 'modal-body');
  const summary = el('div', 'status-list');
  const row = (label, value) => {
    const div = el('div');
    div.append(el('span', '', label), el('b', '', value));
    return div;
  };
  summary.append(
    row('Host', host.name),
    row('Package manager', preview.package_manager || 'unknown'),
    row('Reboot required', preview.reboot_required ? 'yes' : 'no'),
  );
  body.append(summary);
  const previewBox = el('div');
  renderPackagePreview(previewBox, preview);
  body.append(previewBox);
  const actions = el('div', 'modal-actions');
  const close = el('button', 'btn', 'Close');
  close.type = 'button';
  actions.append(close);
  body.append(actions);
  const closeFn = openModal('Package details — ' + host.name, body, null, 'wide');
  close.addEventListener('click', closeFn);
}

async function showPatchModal(host) {
  if (hostCanUseJobs(host)) {
    await createJob('patch-preview', [host]);
    return;
  }
  showPatchModalInteractive(host);
}

function showPatchModalInteractive(host) {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'HIBP resolves the package transaction first. Nothing is installed, upgraded, or removed until you review the list and confirm.'));
  const facts = host.facts || {};
  const summary = el('div', 'status-list');
  const row = (label, value) => {
    const div = el('div');
    div.append(el('span', '', label), el('b', '', value));
    return div;
  };
  summary.append(
    row('Host', host.name),
    row('Package manager', facts.package_manager || 'unknown'),
    row('APT upgrade mode', host.apt_upgrade_mode === 'full' ? 'full' : 'safe'),
    row('Pending updates', String(facts.pending_updates || 0)),
    row('Reboot required', facts.reboot_required ? 'yes' : 'no'),
  );
  body.append(summary);
  if (host.apt_upgrade_mode === 'full') {
    body.append(el('p', 'preview-warning', 'Full-upgrade mode can install new dependencies and remove packages. Review every removal before applying.'));
  }
  const previewBox = el('div');
  previewBox.append(el('div', 'muted', 'Resolving package changes…'));
  body.append(previewBox);
  const confirmWrap = el('label', 'field preview-confirm hidden');
  confirmWrap.append(el('span', '', 'This preview includes removals. Type APPLY to confirm.'));
  const confirmInput = el('input');
  confirmInput.type = 'text';
  confirmInput.autocomplete = 'off';
  confirmInput.placeholder = 'APPLY';
  confirmWrap.append(confirmInput);
  body.append(confirmWrap);
  const rebootAfterPatch = el('label', 'field checkbox-field');
  const rebootCheck = el('input');
  rebootCheck.type = 'checkbox';
  rebootAfterPatch.append(rebootCheck, document.createTextNode('Reboot automatically after apply when the target reports a reboot is required'));
  body.append(rebootAfterPatch);
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const refresh = el('button', 'btn', 'Re-preview');
  refresh.type = 'button';
  const apply = el('button', 'btn danger', 'Apply updates');
  apply.type = 'button';
  apply.disabled = true;
  actions.append(cancel, refresh, apply);
  body.append(actions);
  const close = openModal('Patch preview — ' + host.name, body, null, 'wide');
  let current = null;
  let cancelled = false;
  const syncApply = () => {
    const counts = current ? previewCounts(current.preview) : { remove: 0 };
    const total = current ? previewTotal(current.preview) : 0;
    const confirmed = counts.remove === 0 || confirmInput.value.trim().toUpperCase() === 'APPLY';
    apply.disabled = !current || total === 0 || !confirmed;
  };
  const load = async () => {
    current = null;
    apply.disabled = true;
    refresh.disabled = true;
    confirmWrap.classList.add('hidden');
    previewBox.replaceChildren(el('div', 'muted', 'Resolving package changes…'));
    beginOperation('Patch preview — ' + host.name, 'Resolving package changes with ' + (facts.package_manager || 'the package manager') + '…');
    try {
      const response = await fetchPatchPreview(host);
      if (cancelled) return;
      current = response;
      renderPackagePreview(previewBox, response.preview);
      const counts = previewCounts(response.preview);
      const total = previewTotal(response.preview);
      if (counts.remove > 0) {
        confirmWrap.classList.remove('hidden');
        confirmInput.value = '';
      }
      syncApply();
      finishOperation(
        total ? 'Patch preview ready — ' + host.name : 'Everything is up to date — ' + host.name,
        total ? total + ' package change(s) reviewed' : 'No package changes found.',
      );
    } catch (error) {
      previewBox.replaceChildren(el('div', 'preview-warning', error.message));
      previewBox.append(el('p', 'muted', 'If this host is running an older HIBP helper, run Setup / Update helpers first so the fixed preview action is installed.'));
      finishOperation('Patch preview failed — ' + host.name, error.message, true);
    } finally {
      refresh.disabled = false;
    }
  };
  cancel.addEventListener('click', () => {
    cancelled = true;
    if (operationState.active) finishOperation('Patch preview cancelled', 'No changes were made.');
    close();
  });
  refresh.addEventListener('click', () => {
    cancelled = false;
    load();
  });
  confirmInput.addEventListener('input', syncApply);
  apply.addEventListener('click', () => {
    if (!current) return;
    const counts = previewCounts(current.preview);
    if (counts.remove > 0 && confirmInput.value.trim().toUpperCase() !== 'APPLY') return;
    if (!confirm('Apply these package changes on ' + host.name + '? This runs the root-owned helper on the target.')) return;
    close();
    applyPatchHost(host, current.preview, current.preview_hash, rebootCheck.checked);
  });
  load();
}

async function applyPatchHost(host, preview, previewHash, rebootAfterPatch = false) {
  const counts = previewCounts(preview);
  beginOperation('Applying updates — ' + host.name, 'Interactive fallback is running the package manager; keep this tab open. Key-auth hosts use the durable job flow.');
  try {
    const password = await passwordFor(host);
    const result = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/patch',
      (sudoPassword) => ({
        dry_run: false, confirm: 'apply', preview_hash: previewHash,
        allow_removals: counts.remove > 0,
        password, sudo_password: sudoPassword,
        reboot_after_patch: rebootAfterPatch,
      }),
      { method: 'POST' },
    );
    if (result.no_changes) {
      finishOperation('Nothing to apply — ' + host.name, 'The package state is already current.');
    } else if (result.ok) {
      finishOperation('Patch complete — ' + host.name, result.facts ? 'Facts refreshed automatically.' : 'Updates applied.');
    } else {
      finishOperation('Patch failed — ' + host.name, result.error || 'The package manager reported an error.', true);
    }
    showOutputModal('Patch run — ' + host.name, result);
    if (!result.ok && result.error) toast(result.error, 'error');
    await loadAll({ force: true });
  } catch (error) {
    if (error.status === 409 && error.data && error.data.code === 'preview_changed') {
      finishOperation('Preview changed — ' + host.name, 'The package list changed before apply. Re-open the preview.', true);
      toast('The package list changed. Review it again before applying.', 'error');
      showPatchModal(host);
      return;
    }
    if (error.status === 400 && error.data && error.data.code === 'removals_not_confirmed') {
      finishOperation('Removals need confirmation — ' + host.name, 'The preview includes removals.', true);
      toast('This preview includes package removals. Confirm them first.', 'error');
      showPatchModal(host);
      return;
    }
    finishOperation('Patch failed — ' + host.name, error.message, true);
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

async function showFleetPatchModal(hosts) {
  const targets = hosts.slice();
  if (!targets.length) {
    toast('Select at least one host', 'error');
    return;
  }
  if (!confirm('Preview pending package changes on ' + targets.length + ' selected host(s)?\\n\\nThis creates a durable preview job. You can review the result in the Activity panel and then apply it.')) return;
  await createJob('patch-preview', targets);
}

function showPatchReview(hosts, previews) {
  const targets = hosts.slice();
  const removals = targets.reduce((sum, host) => {
    const entry = previews.get(host.id);
    return sum + (entry ? previewCounts(entry.preview).remove : 0);
  }, 0);
  const changes = targets.reduce((sum, host) => {
    const entry = previews.get(host.id);
    return sum + (entry ? previewTotal(entry.preview) : 0);
  }, 0);
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'This is the reviewed package transaction. Applying it creates a durable server-side job, so you can navigate away or close this dialog. HIBP re-checks every preview immediately before applying and refuses a host if the package list changed.'));

  const summary = el('div', 'status-list');
  const summaryRow = (label, value) => {
    const div = el('div');
    div.append(el('span', '', label), el('b', '', value));
    return div;
  };
  summary.append(
    summaryRow('Hosts in review', String(targets.length)),
    summaryRow('Package changes', String(changes)),
    summaryRow('Removals', String(removals)),
  );
  body.append(summary);

  if (targets.length === 1) {
    const entry = previews.get(targets[0].id);
    const previewBox = el('div');
    renderPackagePreview(previewBox, entry.preview);
    body.append(previewBox);
  } else {
    const wrap = el('div', 'fleet-update-list');
    const table = el('table');
    const head = el('tr');
    for (const label of ['Host', 'Status', 'Upgrade', 'Install', 'Remove', 'Details']) head.append(el('th', '', label));
    table.append(head);
    for (const host of targets) {
      const entry = previews.get(host.id);
      if (!entry) continue;
      const counts = previewCounts(entry.preview);
      const total = previewTotal(entry.preview);
      const row = el('tr');
      row.append(el('td', '', host.name));
      const statusTd = el('td');
      statusTd.append(el('span', 'pill ' + (total ? 'review' : 'reachable'), total ? 'ready' : 'up to date'));
      row.append(statusTd);
      row.append(el('td', '', String(counts.upgrade + counts.downgrade + counts.reinstall)));
      row.append(el('td', '', String(counts.install)));
      row.append(el('td', '', String(counts.remove)));
      const detailsTd = el('td');
      const details = el('button', 'link-button preview-detail-link', 'View');
      details.type = 'button';
      details.disabled = !total;
      details.addEventListener('click', () => showPreviewDetailsModal(host, entry.preview));
      detailsTd.append(details);
      row.append(detailsTd);
      table.append(row);
    }
    wrap.append(table);
    body.append(wrap);
  }

  const confirmWrap = el('label', 'field preview-confirm hidden');
  confirmWrap.append(el('span', '', 'At least one host has package removals. Type APPLY to confirm all removals.'));
  const confirmInput = el('input');
  confirmInput.type = 'text';
  confirmInput.autocomplete = 'off';
  confirmInput.placeholder = 'APPLY';
  confirmWrap.append(confirmInput);
  if (removals > 0) confirmWrap.classList.remove('hidden');
  body.append(confirmWrap);

  const rebootAfterPatch = el('label', 'field checkbox-field');
  const rebootCheck = el('input');
  rebootCheck.type = 'checkbox';
  rebootAfterPatch.append(rebootCheck, document.createTextNode('Reboot automatically after apply when a target reports a reboot is required'));
  body.append(rebootAfterPatch);

  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Close');
  cancel.type = 'button';
  const refresh = el('button', 'btn', 'Re-preview');
  refresh.type = 'button';
  const apply = el('button', 'btn danger', 'Apply reviewed updates');
  apply.type = 'button';
  const syncApply = () => {
    apply.disabled = changes === 0 || (removals > 0 && confirmInput.value.trim().toUpperCase() !== 'APPLY');
  };
  syncApply();
  actions.append(cancel, refresh, apply);
  body.append(actions);
  const close = openModal('Patch review — ' + targets.length + ' host' + (targets.length === 1 ? '' : 's'), body, null, 'wide');
  cancel.addEventListener('click', close);
  refresh.addEventListener('click', async () => {
    close();
    await createJob('patch-preview', targets);
  });
  confirmInput.addEventListener('input', syncApply);
  apply.addEventListener('click', async () => {
    if (apply.disabled) return;
    const spec = {};
    const selected = [];
    for (const host of targets) {
      const entry = previews.get(host.id);
      if (!entry || previewTotal(entry.preview) === 0) continue;
      selected.push(host);
      spec[host.id] = {
        preview_hash: entry.preview_hash,
        allow_removals: previewCounts(entry.preview).remove > 0,
      };
    }
    if (!selected.length) {
      toast('No package changes to apply', 'error');
      return;
    }
    if (!confirm('Apply the reviewed package changes on ' + selected.length + ' host' + (selected.length === 1 ? '' : 's') + '? This creates a durable job and runs the root-owned helper on each target.')) return;
    close();
    await createJob('patch-apply', selected, {
      confirm: 'apply',
      reboot_after_patch: rebootCheck.checked,
      previews: spec,
    });
  });
}

function showCleanupReview(entries) {
  const list = entries.filter((entry) => entry.result && entry.result.count > 0);
  if (!list.length) {
    toast('No orphaned packages to remove', 'error');
    return;
  }
  const total = list.reduce((sum, entry) => sum + Number(entry.result.count || 0), 0);
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Review the orphaned package list. Removal creates a durable server-side job; the helper recomputes the list on each target and removes only what its own package manager reports. This cannot be undone.'));
  const packages = el('pre', 'cleanup-list');
  packages.textContent = list.map(({ host, result }) =>
    host.name + ' (' + (result.package_manager || 'unknown') + '):\n  ' + (result.packages || []).join('\n  ')).join('\n\n');
  body.append(packages);
  const confirmWrap = el('label', 'field');
  confirmWrap.append(el('span', '', 'Type CLEAN to remove these packages (case-insensitive)'));
  const confirmInput = el('input');
  confirmInput.type = 'text';
  confirmInput.autocomplete = 'off';
  confirmInput.placeholder = 'CLEAN';
  confirmWrap.append(confirmInput);
  body.append(confirmWrap);
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Close');
  cancel.type = 'button';
  const remove = el('button', 'btn danger', 'Remove ' + total + ' package' + (total === 1 ? '' : 's'));
  remove.type = 'button';
  remove.disabled = true;
  actions.append(cancel, remove);
  body.append(actions);
  const close = openModal('Cleanup review — ' + list.length + ' host' + (list.length === 1 ? '' : 's'), body);
  cancel.addEventListener('click', close);
  confirmInput.addEventListener('input', () => {
    remove.disabled = confirmInput.value.trim().toUpperCase() !== 'CLEAN';
  });
  remove.addEventListener('click', async () => {
    if (remove.disabled) return;
    close();
    await createJob('cleanup-apply', list.map((entry) => entry.host), { confirm: 'cleanup' });
  });
  confirmInput.focus();
}

function addPackageEnvRow(container, key = '', value = '') {
  const row = el('div', 'env-row');
  const keyInput = el('input');
  keyInput.type = 'text';
  keyInput.placeholder = 'WAZUH_MANAGER';
  keyInput.value = key;
  keyInput.autocomplete = 'off';
  keyInput.spellcheck = false;
  const valueInput = el('input');
  valueInput.type = 'text';
  valueInput.placeholder = '10.0.0.5';
  valueInput.value = value;
  valueInput.autocomplete = 'off';
  valueInput.spellcheck = false;
  const remove = el('button', 'btn small', '×');
  remove.type = 'button';
  remove.title = 'Remove variable';
  remove.addEventListener('click', () => row.remove());
  row.append(keyInput, valueInput, remove);
  container.append(row);
}

function readPackageEnvRows(container) {
  const env = {};
  for (const row of container.querySelectorAll('.env-row')) {
    const [keyInput, valueInput] = row.querySelectorAll('input');
    const key = keyInput.value.trim();
    const value = valueInput.value;
    if (!key && !value) continue;
    if (!key) throw new Error('Every installer variable needs a name');
    env[key] = value;
  }
  return env;
}

async function uploadPackageJob(hosts, file, env) {
  const form = new FormData();
  form.append('host_ids', JSON.stringify(hosts.map((host) => host.id)));
  form.append('env', JSON.stringify(env));
  form.append('confirm', 'install');
  form.append('package', file, file.name);
  const response = await fetch('/api/v1/jobs/package', {
    method: 'POST',
    body: form,
    headers: withDemoSession(new Headers()),
    credentials: 'same-origin',
    cache: 'no-store',
  });
  const text = await response.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (!response.ok) {
    if (response.status === 401 || (response.status === 403 && data.code === 'mfa_required')) {
      showAuthScreen();
    }
    throw new Error(data.error || ('HTTP ' + response.status));
  }
  return data;
}

function openDeployPackageFlow() {
  if (!selectedHosts().length) {
    setView('hosts');
    toast('Select one or more hosts, then click Deploy package again.');
    return;
  }
  showDeployPackageModal();
}

function showDeployPackageModal(hosts) {
  const targets = (hosts && hosts.length ? hosts : selectedHosts()).slice();
  if (!targets.length) {
    toast('Select one or more hosts first', 'error');
    return;
  }
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Upload one signed package and deploy it to the selected hosts. HIBP stages the file in a temporary directory on the controller, transfers it over SSH, verifies its SHA-256, installs it with the target package manager, and removes the temporary copies. The package maintainer scripts run as root.'));
  body.append(el('p', 'preview-warning', 'Only deploy packages you obtained from a trusted source. HIBP verifies the upload hash but does not replace your distribution or vendor signature policy. Installer environment values are stored in the encrypted job record and are never returned by the API. Targets must already run a helper build and sudoers rule that include install-package; run Update helpers first after a controller upgrade.' + (state.status.demo ? ' Demo mode discards the upload and simulates installation; do not enter real secrets.' : '')));
  const drop = el('div', 'package-drop');
  const fileInput = el('input');
  fileInput.type = 'file';
  fileInput.accept = '.deb,.rpm,.pkg.tar.zst,.apk';
  const fileLabel = el('div', 'package-file', 'No package selected');
  fileInput.addEventListener('change', () => {
    const file = fileInput.files && fileInput.files[0];
    fileLabel.textContent = file ? file.name + ' · ' + (file.size / (1024 * 1024)).toFixed(1) + ' MiB' : 'No package selected';
  });
  drop.append(fileInput, fileLabel);
  body.append(drop);
  body.append(el('div', 'muted', 'Selected hosts'));
  body.append(el('div', 'package-hosts', targets.map((host) => {
    let note = '';
    if (host.auth_type !== 'key') note = ' · password auth (will be skipped)';
    else if (!host.trusted_key) note = ' · key not trusted (will be skipped)';
    return host.name + ' · ' + host.address + note;
  }).join('\n')));
  const envSection = el('div');
  envSection.append(el('div', 'muted', 'Installer environment variables (optional)'));
  const envList = el('div', 'env-list');
  envSection.append(envList);
  const addEnv = el('button', 'link-button', '+ Add variable');
  addEnv.type = 'button';
  addEnv.addEventListener('click', () => addPackageEnvRow(envList));
  envSection.append(addEnv);
  body.append(envSection);
  const confirmWrap = el('label', 'field');
  confirmWrap.append(el('span', '', 'Type INSTALL to confirm deployment (case-insensitive)'));
  const confirmInput = el('input');
  confirmInput.type = 'text';
  confirmInput.autocomplete = 'off';
  confirmInput.placeholder = 'INSTALL';
  confirmWrap.append(confirmInput);
  body.append(confirmWrap);
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const deploy = el('button', 'btn danger', 'Upload and install');
  deploy.type = 'button';
  deploy.disabled = true;
  actions.append(cancel, deploy);
  body.append(actions);
  const close = openModal('Deploy package to ' + targets.length + ' host' + (targets.length === 1 ? '' : 's'), body, null, 'wide');
  cancel.addEventListener('click', close);
  const sync = () => {
    deploy.disabled = !(fileInput.files && fileInput.files.length) || confirmInput.value.trim().toUpperCase() !== 'INSTALL';
  };
  fileInput.addEventListener('change', sync);
  confirmInput.addEventListener('input', sync);
  deploy.addEventListener('click', async () => {
    const file = fileInput.files && fileInput.files[0];
    if (!file || confirmInput.value.trim().toUpperCase() !== 'INSTALL') return;
    const limitMiB = state.status.demo ? 8 : 100;
    if (file.size > limitMiB * 1024 * 1024) {
      toast('Package exceeds the ' + limitMiB + ' MiB limit', 'error');
      return;
    }
    let env;
    try {
      env = readPackageEnvRows(envList);
    } catch (error) {
      toast(error.message, 'error');
      return;
    }
    deploy.disabled = true;
    deploy.textContent = 'Uploading…';
    try {
      const result = await uploadPackageJob(targets, file, env);
      close();
      jobDockState.open = true;
      jobDockState.expanded = true;
      await loadJobs({ silent: true });
      toast('Queued: ' + result.job.title, 'ok');
    } catch (error) {
      toast(error.message, 'error');
      deploy.disabled = false;
      deploy.textContent = 'Upload and install';
    }
  });
}

function showFleetRebootModal(hosts) {
  const requested = hosts.slice();
  if (!requested.length) {
    toast('Select at least one host', 'error');
    return;
  }
  const excluded = requested.filter((host) => isControllerHost(host));
  const targets = requested.filter((host) => !isControllerHost(host));
  if (!targets.length) {
    toast('The controller is excluded from bulk reboot; select managed hosts only', 'error');
    return;
  }
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'This is a destructive action. The selected hosts will reboot immediately and their SSH connections may drop. This creates a durable job; reboots run sequentially, one host at a time, and you can continue using other views while it runs.'));
  if (excluded.length) {
    body.append(el('p', 'field-note', 'The controller is excluded from this bulk reboot: ' + excluded.map((host) => host.name).join(', ') + '. Use the per-host Reboot button only if you deliberately want to reboot the controller.'));
  }
  const summary = el('div', 'status-list');
  const row = (label, value) => {
    const div = el('div');
    div.append(el('span', '', label), el('b', '', value));
    return div;
  };
  const rebootRequired = targets.filter((host) => (host.facts || {}).reboot_required).length;
  summary.append(
    row('Selected hosts', String(targets.length)),
    row('Reboot required', String(rebootRequired)),
  );
  body.append(summary);
  const wrap = el('div', 'scroll-list');
  const table = el('table');
  const head = el('tr');
  for (const label of ['Host', 'Reboot required', 'Address']) head.append(el('th', '', label));
  table.append(head);
  for (const host of targets) {
    const tr = el('tr');
    tr.append(
      el('td', '', host.name),
      el('td', '', (host.facts || {}).reboot_required ? 'yes' : 'no'),
      el('td', '', host.address),
    );
    table.append(tr);
  }
  wrap.append(table);
  body.append(wrap);
  const confirmWrap = el('label', 'field');
  confirmWrap.append(el('span', '', 'Type REBOOT to confirm (case-insensitive)'));
  const confirmInput = el('input');
  confirmInput.type = 'text';
  confirmInput.autocomplete = 'off';
  confirmInput.placeholder = 'REBOOT';
  confirmWrap.append(confirmInput);
  body.append(confirmWrap);
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const reboot = el('button', 'btn danger', 'Reboot now');
  reboot.type = 'button';
  const confirmed = () => confirmInput.value.trim().toUpperCase() === 'REBOOT';
  reboot.disabled = true;
  actions.append(cancel, reboot);
  body.append(actions);
  const close = openModal('Reboot ' + targets.length + ' selected host' + (targets.length === 1 ? '' : 's'), body);
  cancel.addEventListener('click', close);
  confirmInput.addEventListener('input', () => {
    reboot.disabled = !confirmed();
  });
  confirmInput.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    if (!confirmed()) {
      reboot.disabled = true;
      return;
    }
    close();
    createJob('reboot', targets, { confirm: 'reboot' });
  });
  reboot.addEventListener('click', () => {
    if (!confirmed()) return;
    close();
    createJob('reboot', targets, { confirm: 'reboot' });
  });
  confirmInput.focus();
}

async function rebootHost(host) {
  if (hostCanUseJobs(host) && !isControllerHost(host)) {
    if (!confirm('Reboot ' + host.name + ' now as a durable background job? The host will go down immediately and the SSH connection may drop.')) return;
    await createJob('reboot', [host], { confirm: 'reboot' });
    return;
  }
  await rebootHostInteractive(host);
}

async function rebootHostInteractive(host) {
  if (!confirm('Reboot ' + host.name + ' now? The host will go down immediately and the SSH connection may drop.')) return;
  toast('Rebooting ' + host.name + '…');
  beginOperation('Rebooting — ' + host.name, 'Requesting a reboot through the fixed helper…');
  try {
    const password = await passwordFor(host);
    const result = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/reboot',
      (sudoPassword) => ({ confirm: 'reboot', password, sudo_password: sudoPassword, allow_controller: true }),
      { method: 'POST' },
    );
    showOutputModal('Reboot requested — ' + host.name, {
      ...result,
      output: result.output || 'Reboot request accepted. The host may disconnect now.',
    });
    finishOperation('Reboot requested — ' + host.name, 'The host may disconnect now.', !result.ok);
    await loadAll({ force: true });
  } catch (error) {
    finishOperation('Reboot failed — ' + host.name, error.message, true);
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

async function showCleanupModal(host) {
  if (hostCanUseJobs(host) && !isControllerHost(host)) {
    if (!confirm('Scan ' + host.name + ' for orphaned packages as a durable background job?')) return;
    await createJob('cleanup-preview', [host]);
    return;
  }
  showCleanupModalInteractive(host);
}

function showCleanupModalInteractive(host) {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Checking for orphaned packages on ' + host.name + '…'));
  const close = openModal('Cleanup — ' + host.name, body);
  (async () => {
    beginOperation('Cleanup preview — ' + host.name, 'Scanning for orphaned packages…');
    try {
      const password = await passwordFor(host);
      const result = await requestWithSudo(
        host,
        '/api/v1/hosts/' + encodeURIComponent(host.id) + '/cleanup',
        (sudoPassword) => ({ dry_run: true, password, sudo_password: sudoPassword, allow_controller: true }),
        { method: 'POST' },
      );
      close();
      finishOperation('Cleanup preview ready — ' + host.name, (result.packages || []).length + ' orphaned package(s)');
      showCleanupPreview(host, result);
    } catch (error) {
      close();
      finishOperation('Cleanup preview failed — ' + host.name, error.message, true);
      if (error.message !== 'cancelled') toast(error.message, 'error');
    }
  })();
}

function showCleanupPreview(host, preview) {
  const body = el('div', 'modal-body');
  if (!preview.supported) {
    body.append(el('p', '', preview.output || ('Cleanup is not supported for ' + (preview.package_manager || 'this host') + '.')));
    const actions = el('div', 'modal-actions');
    const closeButton = el('button', 'btn', 'Close');
    closeButton.type = 'button';
    actions.append(closeButton);
    body.append(actions);
    const close = openModal('Cleanup — ' + host.name, body);
    closeButton.addEventListener('click', close);
    return;
  }
  if (!preview.ok) {
    body.append(el('p', 'auth-message', preview.error || 'Cleanup check failed.'));
    if (preview.output) body.append(el('pre', 'cleanup-list', preview.output));
    const actions = el('div', 'modal-actions');
    const closeButton = el('button', 'btn', 'Close');
    closeButton.type = 'button';
    actions.append(closeButton);
    body.append(actions);
    const close = openModal('Cleanup — ' + host.name, body);
    closeButton.addEventListener('click', close);
    return;
  }
  const packages = preview.packages || [];
  if (!packages.length) {
    body.append(el('p', '', 'No orphaned packages found on ' + host.name + '.'));
    if (preview.output) body.append(el('pre', 'cleanup-list', preview.output));
    const actions = el('div', 'modal-actions');
    const closeButton = el('button', 'btn', 'Close');
    closeButton.type = 'button';
    actions.append(closeButton);
    body.append(actions);
    const close = openModal('Cleanup — ' + host.name, body);
    closeButton.addEventListener('click', close);
    return;
  }
  const summary = el('div', 'status-list');
  const row = (label, value) => {
    const div = el('div');
    div.append(el('span', '', label), el('b', '', value));
    return div;
  };
  summary.append(
    row('Host', host.name),
    row('Package manager', preview.package_manager || 'unknown'),
    row('Orphaned packages', String(packages.length)),
  );
  body.append(summary);
  body.append(el('p', 'muted', 'Review the package list. Removal runs the fixed helper on the target and cannot be undone.'));
  body.append(el('pre', 'cleanup-list', packages.join('\n')));
  const confirmWrap = el('label', 'field');
  confirmWrap.append(el('span', '', 'Type CLEAN to confirm (case-insensitive)'));
  const confirmInput = el('input');
  confirmInput.type = 'text';
  confirmInput.autocomplete = 'off';
  confirmInput.placeholder = 'CLEAN';
  confirmWrap.append(confirmInput);
  body.append(confirmWrap);
  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const remove = el('button', 'btn danger', 'Remove ' + packages.length + ' package' + (packages.length === 1 ? '' : 's'));
  remove.type = 'button';
  const confirmed = () => confirmInput.value.trim().toUpperCase() === 'CLEAN';
  remove.disabled = true;
  actions.append(cancel, remove);
  body.append(actions);
  const close = openModal('Cleanup — ' + host.name, body);
  cancel.addEventListener('click', close);
  confirmInput.addEventListener('input', () => {
    remove.disabled = !confirmed();
  });
  confirmInput.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' || !confirmed()) return;
    event.preventDefault();
    close();
    applyCleanup(host);
  });
  remove.addEventListener('click', () => {
    if (!confirmed()) return;
    close();
    applyCleanup(host);
  });
  confirmInput.focus();
}

async function applyCleanup(host) {
  toast('Removing orphaned packages on ' + host.name + '…');
  beginOperation('Removing orphaned packages — ' + host.name, 'Running the fixed helper on the target…');
  try {
    const password = await passwordFor(host);
    const result = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/cleanup',
      (sudoPassword) => ({
        dry_run: false, confirm: 'cleanup', password, sudo_password: sudoPassword,
        allow_controller: true,
      }),
      { method: 'POST' },
    );
    showOutputModal('Cleanup — ' + host.name, {
      ...result,
      output: result.output || result.error || 'Cleanup finished.',
    });
    if (result.ok) {
      finishOperation('Cleanup complete — ' + host.name,
        result.remaining >= 0 ? result.remaining + ' package(s) remaining' : 'Removal finished.');
      toast('Cleanup finished on ' + host.name +
        (result.remaining >= 0 ? ', ' + result.remaining + ' package(s) remaining' : ''), 'ok');
    } else {
      finishOperation('Cleanup failed — ' + host.name, result.error || 'The helper reported an error.', true);
      if (result.error) toast(result.error, 'error');
    }
    await loadAll({ force: true });
  } catch (error) {
    finishOperation('Cleanup failed — ' + host.name, error.message, true);
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

async function showFleetCleanupModal(hosts) {
  const requested = hosts.slice();
  if (!requested.length) {
    toast('Select at least one host', 'error');
    return;
  }
  const excluded = requested.filter((host) => isControllerHost(host));
  const targets = requested.filter((host) => !isControllerHost(host));
  if (!targets.length) {
    toast('The controller is excluded from bulk cleanup; select managed hosts only', 'error');
    return;
  }
  if (excluded.length) toast('The controller is excluded from bulk cleanup', 'error');
  if (!confirm('Scan ' + targets.length + ' selected host(s) for orphaned packages as a durable background job?\\n\\nYou will review the package lists and type CLEAN before anything is removed.')) return;
  await createJob('cleanup-preview', targets);
}

function detailCard(title, rows) {
  const card = el('div', 'detail-card');
  card.append(el('h3', '', title));
  for (const [label, value] of rows) {
    const line = el('p');
    line.append(el('span', '', label + ': '), el('b', '', value === undefined || value === null || value === '' ? '—' : String(value)));
    card.append(line);
  }
  return card;
}

function detailSection(title, content) {
  const card = el('div', 'detail-card');
  card.append(el('h3', '', title), content);
  return card;
}

function metricCard(label, samples, key, color) {
  const card = el('div', 'metric-card');
  const latest = samples.length ? Number(samples[samples.length - 1][key] || 0) : 0;
  card.append(el('div', 'muted', label), el('div', 'metric-value', latest.toFixed(1) + '%'));
  const canvas = document.createElement('canvas');
  canvas.width = 320;
  canvas.height = 70;
  card.append(canvas);
  const ctx = canvas.getContext('2d');
  if (!ctx) return card;
  ctx.strokeStyle = 'rgba(139,160,189,.18)';
  ctx.lineWidth = 1;
  for (let y = 0; y <= canvas.height; y += canvas.height / 2) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(canvas.width, y);
    ctx.stroke();
  }
  if (samples.length >= 2) {
    ctx.beginPath();
    const stepX = canvas.width / (samples.length - 1);
    samples.forEach((sample, index) => {
      const value = Math.max(0, Math.min(100, Number(sample[key] || 0)));
      const y = canvas.height - (value / 100) * (canvas.height - 4) - 2;
      if (index === 0) ctx.moveTo(0, y);
      else ctx.lineTo(index * stepX, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();
  } else {
    card.append(el('div', 'hint', 'Waiting for metric samples…'));
  }
  return card;
}

function renderOverviewPanel(panel, data, host) {
  panel.replaceChildren();
  const facts = (data.host && data.host.facts) || {};
  const key = data.host && data.host.trusted_key;
  const grid = el('div', 'detail-grid');
  grid.append(
    detailCard('Connection', [
      ['Address', host.address + ':' + host.port],
      ['SSH user', host.username],
      ['Auth', host.auth_type],
      ['Proxy jump', host.proxy_jump ? (host.proxy_jump.username ? host.proxy_jump.username + '@' : '') + host.proxy_jump.address + ':' + (host.proxy_jump.port || 22) : ''],
      ['Status', host.status || 'unknown'],
    ]),
    detailCard('Operating system', [
      ['OS', facts.os_pretty_name],
      ['Kernel', facts.kernel],
      ['Package manager', facts.package_manager],
      ['APT upgrade mode', host.apt_upgrade_mode || 'safe'],
      ['Helper build', buildCompact(facts.agent) || 'not reported'],
      ['Uptime', formatUptime(facts.uptime_seconds)],
    ]),
    detailCard('Patch state', [
      ['Pending updates', facts.pending_updates],
      ['Orphaned packages', facts.cleanup_supported ? facts.orphaned_packages : 'not supported'],
      ['Reboot required', facts.reboot_required ? 'yes' : 'no'],
      ['Facts collected', facts.collected_at ? new Date(facts.collected_at).toLocaleString() : ''],
    ]),
    detailCard('Trust', [
      ['Host key', key ? key.key_type + ' ' + key.fingerprint : 'not trusted'],
      ['Group', host.group_name],
      ['Tags', host.tags],
      ['CMDB CI ID', host.cmdb_ci_id],
    ]),
  );
  panel.append(grid);
}

function renderSystemPanel(panel, data, host, reload, onMetricsDaysChange = async () => {}) {
  panel.replaceChildren();
  const metrics = data.metrics || [];
  const metricsDays = Number(data.metrics_days) || 30;
  const metricHead = el('div', 'metric-head');
  const metricSummary = el('div', 'muted');
  if (metrics.length) {
    const first = new Date(metrics[0].collected_at).toLocaleString();
    const last = new Date(metrics[metrics.length - 1].collected_at).toLocaleString();
    metricSummary.textContent = 'Last ' + metricsDays + ' days · ' + metrics.length.toLocaleString() + ' samples · ' + first + ' → ' + last;
  } else {
    metricSummary.textContent = 'No samples in the last ' + metricsDays + ' days.';
  }
  const range = el('select', 'metric-range');
  range.setAttribute('aria-label', 'Metric history range');
  for (const [days, label] of [[1, '24 hours'], [7, '7 days'], [10, '10 days'], [30, '30 days'], [90, '90 days']]) {
    const option = el('option', '', label);
    option.value = String(days);
    option.selected = days === metricsDays;
    range.append(option);
  }
  range.addEventListener('change', async () => {
    try {
      await onMetricsDaysChange(Number(range.value));
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  metricHead.append(metricSummary, range);
  panel.append(metricHead);
  const metricGrid = el('div', 'metric-grid');
  metricGrid.append(
    metricCard('CPU', metrics, 'cpu_percent', '#5eead4'),
    metricCard('Memory', metrics, 'memory_percent', '#f4b740'),
    metricCard('Disk /', metrics, 'disk_percent', '#f26d6d'),
  );
  panel.append(metricGrid);

  const info = data.system_info;
  if (!info) {
    panel.append(el('p', 'muted', 'No system information has been collected yet.'));
  } else {
    const cpu = info.cpu || {};
    const memory = info.memory || {};
    const swap = info.swap || {};
    const systemd = info.systemd || {};
    const docker = info.docker || {};
    const grid = el('div', 'detail-grid');
    grid.append(
      detailCard('CPU', [
        ['Model', cpu.model],
        ['Cores', cpu.cores],
        ['Usage', (Number(cpu.usage_percent) || 0).toFixed(1) + '%'],
        ['Load', [cpu.load1, cpu.load5, cpu.load15].map((v) => Number(v || 0).toFixed(2)).join(' / ')],
      ]),
      detailCard('Memory', [
        ['Total', formatBytes(memory.total_bytes)],
        ['Used', formatBytes(memory.used_bytes)],
        ['Available', formatBytes(memory.available_bytes)],
        ['Usage', (Number(memory.used_percent) || 0).toFixed(1) + '%'],
        ['Swap used', (Number(swap.used_percent) || 0).toFixed(1) + '%'],
      ]),
      detailCard('Host', [
        ['Hostname', info.hostname],
        ['OS', info.os_pretty_name || info.os],
        ['Kernel', info.kernel],
        ['Architecture', info.arch],
        ['Virtualization', info.virtualization],
        ['Boot time', info.boot_time ? new Date(info.boot_time).toLocaleString() : ''],
        ['Processes', info.processes],
      ]),
      detailCard('Systemd', [
        ['Version', systemd.version],
        ['Running services', systemd.running_services],
        ['Failed units', (systemd.failed_units || []).join(', ') || 'none'],
      ]),
      detailCard('Network', [
        ['Default route', info.default_route],
        ['DNS', (info.dns || []).join(', ')],
      ]),
      detailCard('Docker', [
        ['Available', docker.available ? 'yes' : 'no'],
        ['Engine', docker.version],
        ['Compose', docker.compose_version],
      ]),
    );
    panel.append(grid);

    const failedUnits = systemd.failed_units || [];
    const runningUnits = systemd.running_units || [];
    if (failedUnits.length || runningUnits.length) {
      const serviceWrap = el('div', 'file-list');
      const serviceSeen = new Set();
      const serviceRows = [];
      for (const unit of failedUnits) {
        if (!serviceSeen.has(unit)) {
          serviceSeen.add(unit);
          serviceRows.push({ unit, state: 'failed' });
        }
      }
      for (const unit of runningUnits) {
        if (!serviceSeen.has(unit)) {
          serviceSeen.add(unit);
          serviceRows.push({ unit, state: 'running' });
        }
      }
      for (const service of serviceRows) {
        const row = el('div', 'file-row');
        row.append(el('span', 'file-name', service.unit));
        row.append(el('span', 'badge ' + (service.state === 'failed' ? 'red' : 'green'), service.state));
        const monitor = el('button', 'btn small', 'Monitor');
        monitor.type = 'button';
        monitor.addEventListener('click', () => showMonitorPreset({
          name: service.unit + ' — ' + service.state,
          type: 'service.systemd',
          target: service.unit,
          interval_seconds: 300,
          repeat_minutes: 60,
          cooldown_minutes: 15,
          enabled: true,
          assignments: [{ scope: 'host', target: host.id }],
        }));
        row.append(monitor);
        serviceWrap.append(row);
      }
      panel.append(detailSection('Services · ' + failedUnits.length + ' failed · ' + runningUnits.length + ' running', serviceWrap));
    } else if (systemd.available) {
      panel.append(detailSection('Services', el('p', 'muted', systemd.units_collected
        ? 'No running or failed units were reported.'
        : 'Unit-level service state is not available from this helper. Run Update helpers on the host to enable service monitoring.')));
    }

    const diskWrap = el('div', 'scroll-list');
    const diskTable = el('table');
    const diskHead = el('tr');
    for (const label of ['Mount', 'Filesystem', 'Used', 'Total', 'Use%']) diskHead.append(el('th', '', label));
    diskTable.append(diskHead);
    for (const diskInfo of info.disks || []) {
      const row = el('tr');
      row.append(el('td', '', diskInfo.mount), el('td', '', diskInfo.filesystem),
        el('td', '', formatBytes(diskInfo.used_bytes)), el('td', '', formatBytes(diskInfo.total_bytes)),
        el('td', '', (Number(diskInfo.used_percent) || 0).toFixed(1) + '%'));
      diskTable.append(row);
    }
    diskWrap.append(diskTable);
    panel.append(detailSection('Disks', diskWrap));

    const networkWrap = el('div', 'scroll-list');
    for (const iface of info.network || []) {
      networkWrap.append(el('div', '', iface.name + (iface.mac ? ' · ' + iface.mac : '') + ' · ' + (iface.addresses || []).join(', ')));
    }
    panel.append(detailSection('Interfaces', networkWrap));

    const listeningWrap = el('div', 'scroll-list');
    for (const line of info.listening || []) listeningWrap.append(el('div', '', line));
    if (!(info.listening || []).length) listeningWrap.append(el('div', '', 'No listening-port data.'));
    panel.append(detailSection('Listening ports', listeningWrap));
  }

  const actions = el('div', 'modal-actions');
  const refreshInfo = el('button', 'btn primary', 'Collect system info');
  refreshInfo.type = 'button';
  refreshInfo.addEventListener('click', async () => {
    try {
      const password = await passwordFor(host);
      await requestWithSudo(host, '/api/v1/hosts/' + encodeURIComponent(host.id) + '/system-info',
        (sudoPassword) => ({ password, sudo_password: sudoPassword }), { method: 'POST' });
      toast('System information updated', 'ok');
      await reload();
    } catch (error) {
      if (error.message !== 'cancelled') toast(error.message, 'error');
    }
  });
  actions.append(refreshInfo);
  panel.append(actions);
  panel.append(renderHostSettings(data, host, reload));
}

function renderHostSettings(data, host, reload) {
  const card = el('div', 'detail-card');
  card.append(el('h3', '', 'Collection settings for this host'));
  card.append(el('p', 'muted', 'Values that match the fleet defaults remain inherited. Only changed values become host overrides.'));
  const grid = el('div', 'settings-grid');
  const enabled = selectField(grid, 'Collector', 'collector_enabled', [['1', 'Enabled'], ['0', 'Disabled']]);
  const metricsInterval = inputField(grid, 'Metrics interval', 'metrics_interval', '5m');
  const factsInterval = inputField(grid, 'Facts interval', 'facts_interval', '12h');
  const retention = inputField(grid, 'Metrics retention (days)', 'retention_days', '30', 'number');
  const eventsEnabled = selectField(grid, 'Event collection', 'events_enabled', [['1', 'Enabled'], ['0', 'Disabled']]);
  const eventsRetention = inputField(grid, 'Event retention (days)', 'events_retention_days', '30', 'number');
  const authWindow = inputField(grid, 'Auth-failure window (minutes)', 'auth_window_minutes', '10', 'number');
  const roots = inputField(grid, 'Docker scan roots', 'docker_roots', '/opt');
  const settings = data.settings || {};
  enabled.value = settings['collector.enabled'] || '1';
  metricsInterval.value = settings['collector.metrics_interval'] || '5m';
  factsInterval.value = settings['collector.facts_interval'] || '12h';
  retention.value = settings['metrics.retention_days'] || '30';
  eventsEnabled.value = settings['events.enabled'] || '1';
  eventsRetention.value = settings['events.retention_days'] || '30';
  authWindow.value = settings['events.auth_window_minutes'] || '10';
  roots.value = settings['docker.scan_roots'] || '/opt';
  card.append(grid);
  const actions = el('div', 'modal-actions');
  const reset = el('button', 'btn', 'Use fleet defaults');
  reset.type = 'button';
  const save = el('button', 'btn primary', 'Save host settings');
  save.type = 'button';
  actions.append(reset, save);
  card.append(actions);
  const fields = {
    'collector.enabled': enabled,
    'collector.metrics_interval': metricsInterval,
    'collector.facts_interval': factsInterval,
    'metrics.retention_days': retention,
    'events.enabled': eventsEnabled,
    'events.retention_days': eventsRetention,
    'events.auth_window_minutes': authWindow,
    'docker.scan_roots': roots,
  };
  const hostSettings = data.host_settings || {};
  const inherited = data.inherited_settings || {};
  const payload = () => {
    const settings = {};
    for (const [key, field] of Object.entries(fields)) {
      const value = field.value.trim();
      const hadOverride = Object.prototype.hasOwnProperty.call(hostSettings, key);
      const inheritedValue = inherited[key] ?? data.settings_defaults?.[key] ?? '';
      // Preserve existing host overrides; create a new override only when the
      // operator actually changed the inherited value. This avoids turning a
      // plain "open and save" into a permanent fleet-default pin.
      if (hadOverride || value !== inheritedValue) settings[key] = value;
    }
    return { scope: 'host', host_id: host.id, settings };
  };
  save.addEventListener('click', async () => {
    try {
      await api('/api/v1/settings', { method: 'PUT', body: JSON.stringify(payload()) });
      toast('Host settings saved', 'ok');
      await reload();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  reset.addEventListener('click', async () => {
    try {
      await api('/api/v1/settings', {
        method: 'PUT',
        body: JSON.stringify({
          scope: 'host', host_id: host.id,
          settings: {
            'collector.enabled': '', 'collector.metrics_interval': '', 'collector.facts_interval': '',
            'metrics.retention_days': '', 'events.enabled': '', 'events.retention_days': '',
            'events.auth_window_minutes': '', 'docker.scan_roots': '',
          },
        }),
      });
      toast('Host now inherits fleet defaults', 'ok');
      await reload();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  return card;
}

function showDockerCheckResult(project, result) {
  const body = el('div', 'modal-body');
  const meta = el('div', 'status-list');
  meta.append(
    detailCard('Project', [['Name', project], ['Result', result.ok ? 'check complete' : 'check failed'], ['Duration', (Number(result.duration_seconds) || 0).toFixed(1) + 's']]),
  );
  body.append(meta);
  const wrap = el('div', 'scroll-list');
  const table = el('table');
  const head = el('tr');
  for (const label of ['Service', 'Image', 'Status', 'Container']) head.append(el('th', '', label));
  table.append(head);
  for (const service of result.services || []) {
    const row = el('tr');
    const statusClass = service.status === 'up-to-date' ? 'reachable'
      : service.status === 'pull-failed' ? 'unreachable'
        : service.status === 'image-updated' || service.status === 'new-image' || service.status === 'container-stale' ? 'review' : 'unknown';
    const status = el('span', 'pill ' + statusClass, service.status);
    const statusCell = el('td');
    statusCell.append(status);
    row.append(el('td', '', service.service), el('td', '', service.image || '—'), statusCell, el('td', '', service.container_id || '—'));
    table.append(row);
  }
  wrap.append(table);
  body.append(wrap);
  if (result.error) body.append(el('pre', 'key-box', result.error));
  const actions = el('div', 'modal-actions');
  const close = el('button', 'btn', 'Close');
  close.type = 'button';
  actions.append(close);
  body.append(actions);
  const closeFn = openModal('Docker check — ' + project, body);
  close.addEventListener('click', closeFn);
}

async function checkDockerProject(host, project, reload) {
  if (!confirm('Pull the latest images for Compose project "' + project + '"? Running containers will not be restarted.')) return;
  try {
    const password = await passwordFor(host);
    const response = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/docker/check',
      (sudoPassword) => ({ project, password, sudo_password: sudoPassword }),
      { method: 'POST' },
    );
    showDockerCheckResult(project, response.result || {});
    await reload();
  } catch (error) {
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

async function applyDockerProject(host, project, reload) {
  const answer = prompt('Type APPLY to recreate containers in Compose project "' + project + '":');
  if (answer !== 'APPLY') return;
  try {
    const password = await passwordFor(host);
    const response = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/docker/apply',
      (sudoPassword) => ({ project, confirm: 'apply', password, sudo_password: sudoPassword }),
      { method: 'POST' },
    );
    const result = response.result || {};
    showOutputModal('Docker apply — ' + project, {
      action: 'docker-apply',
      ok: response.ok,
      exit_code: result.exit_code ?? 0,
      output: result.output || result.error || 'Docker Compose update finished.',
    });
    await reload();
  } catch (error) {
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

async function checkAllDockerProjects(host, reload) {
  if (!confirm('Pull the latest images for all Compose projects on "' + host.name + '"? Running containers will not be restarted.')) return;
  toast('Checking all Docker Compose projects on ' + host.name + '…');
  beginOperation('Docker check — ' + host.name, 'Pulling images and comparing project state…');
  try {
    const password = await passwordFor(host);
    const response = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/docker/check-all',
      (sudoPassword) => ({ password, sudo_password: sudoPassword }),
      { method: 'POST' },
    );
    const result = response || {};
    const body = el('div', 'modal-body');
    body.append(el('p', 'muted', 'Images were pulled and compared. No containers were restarted by this check.'));
    const summary = el('div', 'status-list');
    const row = (label, value) => {
      const div = el('div');
      div.append(el('span', '', label), el('b', '', value));
      return div;
    };
    summary.append(row('Projects checked', String(result.checked || 0)), row('Updates available', String(result.updates || 0)), row('Failed', String(result.failed || 0)));
    body.append(summary);
    const wrap = el('div', 'scroll-list');
    const table = el('table');
    const head = el('tr');
    for (const label of ['Project', 'Status', 'Summary']) head.append(el('th', '', label));
    table.append(head);
    for (const project of result.results || []) {
      const tr = el('tr');
      const statusClass = project.status === 'update-available' ? 'review'
        : project.status === 'up-to-date' ? 'reachable'
          : project.status === 'failed' ? 'unreachable' : 'unknown';
      const statusCell = el('td');
      statusCell.append(el('span', 'pill ' + statusClass, project.status || 'unknown'));
      tr.append(el('td', '', project.project || '—'), statusCell, el('td', '', project.summary || project.error || '—'));
      table.append(tr);
    }
    if (!(result.results || []).length) wrap.append(el('div', '', 'No Compose projects were found.'));
    else wrap.append(table);
    body.append(wrap);
    const actions = el('div', 'modal-actions');
    const close = el('button', 'btn', 'Close');
    close.type = 'button';
    actions.append(close);
    body.append(actions);
    const closeFn = openModal('Docker check all — ' + ((result.results || []).length) + ' projects', body, null, 'wide');
    close.addEventListener('click', closeFn);
    finishOperation('Docker check complete — ' + host.name, 'No containers were restarted.');
    await reload();
  } catch (error) {
    finishOperation('Docker check failed — ' + host.name, error.message, true);
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

async function updateSelectedDockerProjects(host, projects, reload) {
  const selected = projects.slice();
  if (!selected.length) {
    toast('Select at least one Compose project', 'error');
    return;
  }
  const answer = prompt('Type UPDATE to pull images and recreate the ' + selected.length + ' selected Compose project(s) on "' + host.name + '":');
  if (answer !== 'UPDATE') return;
  toast('Updating selected Docker Compose projects on ' + host.name + '…');
  beginOperation('Docker update — ' + host.name, 'Pulling images and recreating ' + selected.length + ' project(s)…');
  try {
    const password = await passwordFor(host);
    const response = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/docker/update-selected',
      (sudoPassword) => ({ projects: selected, confirm: 'update', password, sudo_password: sudoPassword }),
      { method: 'POST' },
    );
    showDockerUpdateAllResult(response, 'Docker update selected');
    finishOperation('Docker update complete — ' + host.name, 'Reviewed projects were recreated.');
    await reload();
  } catch (error) {
    finishOperation('Docker update failed — ' + host.name, error.message, true);
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

async function updateAllDockerProjects(host, reload) {
  const answer = prompt('Type UPDATE to pull images and recreate only changed Compose projects on "' + host.name + '":');
  if (answer !== 'UPDATE') return;
  toast('Updating all Docker Compose projects on ' + host.name + '…');
  beginOperation('Docker update all — ' + host.name, 'Pulling images and recreating changed projects…');
  try {
    const password = await passwordFor(host);
    const response = await requestWithSudo(
      host,
      '/api/v1/hosts/' + encodeURIComponent(host.id) + '/docker/update-all',
      (sudoPassword) => ({ confirm: 'update', password, sudo_password: sudoPassword }),
      { method: 'POST' },
    );
    showDockerUpdateAllResult(response.result || {});
    finishOperation('Docker update complete — ' + host.name, 'Changed projects were recreated.');
    await reload();
  } catch (error) {
    finishOperation('Docker update failed — ' + host.name, error.message, true);
    if (error.message !== 'cancelled') toast(error.message, 'error');
  }
}

function showDockerUpdateAllResult(result, title = 'Docker update all') {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Only Compose projects whose pulled image changed are recreated. Containers in unchanged projects are left running.'));
  const summary = el('div', 'status-list');
  const row = (label, value) => {
    const div = el('div');
    div.append(el('span', '', label), el('b', '', value));
    return div;
  };
  summary.append(
    row('Updated projects', String(result.updated || 0)),
    row('Unchanged projects', String(result.skipped || 0)),
    row('Failed projects', String(result.failed || 0)),
    row('Duration', (Number(result.duration_seconds) || 0).toFixed(1) + 's'),
  );
  body.append(summary);
  const wrap = el('div', 'scroll-list');
  const table = el('table');
  const head = el('tr');
  for (const label of ['Project', 'Action', 'Changed services', 'Detail']) head.append(el('th', '', label));
  table.append(head);
  for (const project of (result.projects || result.results || [])) {
    const row = el('tr');
    const statusClass = project.action === 'updated' ? 'reachable'
      : project.action === 'failed' ? 'unreachable' : 'unknown';
    const action = el('span', 'pill ' + statusClass, project.action || 'unknown');
    const actionCell = el('td');
    actionCell.append(action);
    const changed = (project.check && project.check.services || [])
      .filter((service) => ['new-image', 'image-updated', 'container-stale'].includes(service.status))
      .map((service) => service.service);
    const detail = project.error || (project.apply && project.apply.output) || '—';
    row.append(
      el('td', '', project.name || '—'),
      actionCell,
      el('td', '', changed.length ? changed.join(', ') : '—'),
      el('td', 'alert-detail', String(detail).replace(/\s+/g, ' ').slice(0, 180)),
    );
    table.append(row);
  }
  const projects = result.projects || result.results || [];
  if (!projects.length) {
    wrap.append(el('div', '', 'No Compose projects were found.'));
  } else {
    wrap.append(table);
  }
  body.append(wrap);
  const actions = el('div', 'modal-actions');
  const close = el('button', 'btn', 'Close');
  close.type = 'button';
  actions.append(close);
  body.append(actions);
  const closeFn = openModal(title + ' — ' + projects.length + ' projects', body, null, 'wide');
  close.addEventListener('click', closeFn);
}

function renderServicesPanel(panel, data, host, reload) {
  panel.replaceChildren();
  const baseline = data.service_baseline || [];
  const states = data.service_states || [];
  const baselineByUnit = new Map(baseline.map((item) => [item.unit, item]));
  const stateByUnit = new Map(states.map((item) => [item.unit, item]));
  const units = [...new Set([...baselineByUnit.keys(), ...stateByUnit.keys()])]
    .sort((left, right) => left.localeCompare(right));
  const settings = data.settings || {};
  const hostSettings = data.host_settings || {};
  const inherited = data.inherited_settings || {};

  const intro = el('div', 'detail-card');
  intro.append(el('h3', '', 'Service baseline'));
  intro.append(el('p', 'muted', 'HIBP records the systemd units observed running as the host baseline. The fleet Service baseline monitor alerts when an expected unit stops running or any current unit fails. Excluded units are ignored for both failed and missing alerts. Common on-demand, timer, and boot units such as packagekit.service and systemd-timedated.service are excluded by default; use Include to override. Socket- or timer-activated units that exit by design can look missing; exclude them here.'));
  const grid = el('div', 'settings-grid');
  const enabled = selectField(grid, 'Baseline monitoring', 'baseline_enabled', [
    ['', 'Inherit fleet default'], ['1', 'Enabled'], ['0', 'Disabled'],
  ]);
  enabled.value = Object.prototype.hasOwnProperty.call(hostSettings, 'monitor.service_baseline.enabled')
    ? hostSettings['monitor.service_baseline.enabled'] : '';
  const autoAdd = selectField(grid, 'Add newly running units', 'baseline_auto_add', [
    ['', 'Inherit fleet default'], ['1', 'Enabled'], ['0', 'Disabled'],
  ]);
  autoAdd.value = Object.prototype.hasOwnProperty.call(hostSettings, 'monitor.service_baseline.auto_add')
    ? hostSettings['monitor.service_baseline.auto_add'] : '';
  intro.append(grid);
  const effective = [
    'baseline ' + (settings['monitor.service_baseline.enabled'] === '0' ? 'disabled' : 'enabled'),
    'automatic expansion ' + (settings['monitor.service_baseline.auto_add'] === '0' ? 'disabled' : 'enabled'),
  ];
  intro.append(el('p', 'field-note', 'Effective now: ' + effective.join(' · ') + '. Fleet default for automatic expansion: ' + (inherited['monitor.service_baseline.auto_add'] === '0' ? 'disabled' : 'enabled') + '.'));
  const save = el('button', 'btn primary', 'Save baseline settings');
  save.type = 'button';
  save.addEventListener('click', async () => {
    try {
      await api('/api/v1/settings', {
        method: 'PUT',
        body: JSON.stringify({
          scope: 'host', host_id: host.id,
          settings: {
            'monitor.service_baseline.enabled': enabled.value,
            'monitor.service_baseline.auto_add': autoAdd.value,
          },
        }),
      });
      toast('Baseline settings saved', 'ok');
      await reload();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  intro.append(save);
  panel.append(intro);

  const counts = { expected: 0, excluded: 0, failed: 0, running: 0 };
  for (const item of baseline) {
    if (item.excluded) counts.excluded++;
    else if (item.expected) counts.expected++;
  }
  for (const state of states) {
    if (state.state === 'failed') counts.failed++;
    else if (state.state === 'running') counts.running++;
  }

  const card = el('div', 'detail-card');
  card.append(el('h3', '', 'Baseline units'));
  card.append(el('p', 'muted', baseline.length
    ? counts.expected + ' expected · ' + counts.excluded + ' excluded · ' + counts.running + ' running now · ' + counts.failed + ' failed now'
    : 'No baseline has been collected yet. Collect metrics to seed it from the current running services.'));
  if (baseline.length || states.length) {
    const filter = inputField(card, 'Filter units', 'baseline_filter', 'packagekit, ssh, systemd-');
    const wrap = el('div', 'scroll-list');
    const table = el('table');
    const head = el('tr');
    for (const label of ['Unit', 'Current', 'Baseline', 'Last seen', '']) head.append(el('th', '', label));
    table.append(head);
    const tbody = el('tbody');
    table.append(tbody);
    wrap.append(table);
    card.append(wrap);
    const renderRows = () => {
      const query = filter.value.trim().toLowerCase();
      tbody.replaceChildren();
      let shown = 0;
      for (const unit of units) {
        if (query && !unit.toLowerCase().includes(query)) continue;
        shown++;
        const item = baselineByUnit.get(unit);
        const state = stateByUnit.get(unit);
        const row = el('tr');
        row.append(el('td', '', unit));

        const currentTd = el('td');
        const currentText = state ? state.state : 'not reported';
        const currentClass = currentText === 'running' ? 'reachable'
          : currentText === 'failed' ? 'unreachable' : 'unknown';
        currentTd.append(el('span', 'pill ' + currentClass, currentText));
        row.append(currentTd);

        const baselineTd = el('td');
        const baselineText = item ? (item.excluded ? 'excluded' : item.expected ? 'expected' : 'tracked') : 'not in baseline';
        const baselineClass = item ? (item.excluded ? 'review' : 'reachable') : 'unknown';
        baselineTd.append(el('span', 'pill ' + baselineClass, baselineText));
        row.append(baselineTd);

        const seenValue = (state && state.last_seen) || (item && item.last_seen);
        const seenTd = el('td');
        const seen = el('span', 'nowrap', seenValue ? relativeTime(seenValue) : '—');
        if (seenValue) seen.title = new Date(seenValue).toLocaleString();
        seenTd.append(seen);
        row.append(seenTd);

        const actionTd = el('td');
        const excluded = Boolean(item && item.excluded);
        const toggle = actionButton(excluded ? 'Include' : 'Exclude', async () => {
          try {
            await api('/api/v1/hosts/' + encodeURIComponent(host.id) + '/service-baseline/' + encodeURIComponent(unit), {
              method: 'PUT',
              body: JSON.stringify({ excluded: !excluded }),
            });
            toast(excluded ? 'Unit included in baseline monitoring' : 'Unit excluded from baseline monitoring', 'ok');
            await reload();
          } catch (error) {
            toast(error.message, 'error');
          }
        });
        toggle.title = excluded ? 'Restore failed and missing alerts for this unit' : 'Ignore failed and missing alerts for this unit';
        actionTd.append(toggle);
        row.append(actionTd);
        tbody.append(row);
      }
      if (!shown) {
        const row = el('tr');
        const cell = el('td', 'empty-state', 'No matching units.');
        cell.colSpan = 5;
        row.append(cell);
        tbody.append(row);
      }
    };
    filter.addEventListener('input', renderRows);
    renderRows();
  }
  const actions = el('div', 'modal-actions');
  const reset = el('button', 'btn', 'Reset baseline to current running services');
  reset.type = 'button';
  reset.disabled = counts.running === 0;
  reset.title = counts.running === 0
    ? 'No fresh running services have been reported.'
    : 'Expected units are rebuilt from the current running set; excluded units stay excluded.';
  reset.addEventListener('click', async () => {
    if (!confirm('Reset the service baseline for ' + host.name + ' to the current running services?\n\nExpected units that are no longer running are removed. Excluded units stay excluded.')) return;
    try {
      await api('/api/v1/hosts/' + encodeURIComponent(host.id) + '/service-baseline/reset', { method: 'POST', body: '{}' });
      toast('Service baseline reset', 'ok');
      await reload();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  actions.append(reset);
  card.append(actions);
  panel.append(card);
}

function renderContainersPanel(panel, data, host, reload) {
  panel.replaceChildren();
  const settings = data.settings || {};
  const hostSettings = data.host_settings || {};
  const dockerSettings = el('div', 'detail-card');
  dockerSettings.append(el('h3', '', 'Docker monitoring'));
  dockerSettings.append(el('p', 'muted', 'Disabling Docker monitoring for this host suppresses Docker health, project, and container alerts. Cached inventory remains visible below.'));
  const dockerGrid = el('div', 'settings-grid');
  const dockerEnabled = selectField(dockerGrid, 'Docker monitoring for this host', 'docker_enabled', [
    ['', 'Inherit fleet default'], ['1', 'Enabled'], ['0', 'Disabled'],
  ]);
  dockerEnabled.value = Object.prototype.hasOwnProperty.call(hostSettings, 'monitor.docker.enabled')
    ? hostSettings['monitor.docker.enabled'] : '';
  dockerSettings.append(dockerGrid);
  const dockerEffective = settings['monitor.docker.enabled'] === '0' ? 'disabled' : 'enabled';
  dockerSettings.append(el('p', 'field-note', 'Effective now: Docker monitoring is ' + dockerEffective + '. The fleet Docker health monitor itself can be disabled under Monitoring.'));
  const saveDocker = el('button', 'btn primary', 'Save Docker monitoring');
  saveDocker.type = 'button';
  saveDocker.addEventListener('click', async () => {
    try {
      await api('/api/v1/settings', {
        method: 'PUT',
        body: JSON.stringify({
          scope: 'host', host_id: host.id,
          settings: { 'monitor.docker.enabled': dockerEnabled.value },
        }),
      });
      toast('Docker monitoring setting saved', 'ok');
      await reload();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  dockerSettings.append(saveDocker);
  panel.append(dockerSettings);

  const info = (data.system_info && data.system_info.docker) || {};
  const projects = data.docker_projects || [];
  const containers = data.docker_containers || [];
  const checks = new Map((data.docker_checks || []).map((check) => [check.project, check]));
  const selectedProjects = new Set();
  panel.append(el('p', 'muted', info.available
    ? 'Docker Engine ' + (info.version || 'unknown') + ' · Compose ' + (info.compose_version || 'unknown')
    : 'Docker inventory has not been collected or Docker is not installed.'));

  const projectWrap = el('div', 'detail-grid');
  if (projects.length === 0) {
    const empty = el('p', 'muted', 'No Compose projects cached. Use Collect Docker inventory to discover them.');
    projectWrap.append(empty);
  } else {
    for (const project of projects) {
      const card = el('div', 'detail-card');
      const checkState = checks.get(project.name) || {};
      const head = el('div', 'project-head');
      const select = el('input', 'row-select project-select');
      select.type = 'checkbox';
      select.title = 'Select ' + project.name + ' for update';
      select.setAttribute('aria-label', select.title);
      select.addEventListener('change', () => {
        if (select.checked) selectedProjects.add(project.name);
        else selectedProjects.delete(project.name);
        syncUpdateSelected();
      });
      head.append(select, el('h3', '', project.name));
      card.append(head);
      card.append(el('p', 'muted', (project.status || 'unknown') + (project.config_files ? ' · ' + project.config_files : '')));
      const statusText = checkState.status === 'update-available' ? 'update available'
        : checkState.status === 'up-to-date' ? 'up to date'
          : checkState.status === 'updated' ? 'updated'
            : checkState.status === 'failed' ? 'failed' : 'not checked';
      const statusClass = checkState.status === 'update-available' ? 'review'
        : checkState.status === 'up-to-date' || checkState.status === 'updated' ? 'reachable'
          : checkState.status === 'failed' ? 'unreachable' : 'unknown';
      const status = el('p', 'project-status');
      status.append(el('span', 'pill ' + statusClass, statusText));
      if (checkState.summary) status.append(document.createTextNode(' · ' + checkState.summary));
      if (checkState.checked_at) status.title = 'Checked ' + new Date(checkState.checked_at).toLocaleString();
      card.append(status);
      const projectActions = el('div', 'modal-actions');
      const check = el('button', 'btn small', 'Check updates');
      check.type = 'button';
      check.addEventListener('click', () => checkDockerProject(host, project.name, reload));
      const monitor = el('button', 'btn small', 'Monitor');
      monitor.type = 'button';
      monitor.addEventListener('click', () => showMonitorPreset({
        name: project.name + ' — Compose project',
        type: 'docker.project',
        target: project.name,
        interval_seconds: 300,
        repeat_minutes: 60,
        cooldown_minutes: 15,
        enabled: true,
        assignments: [{ scope: 'host', target: host.id }],
      }));
      const apply = el('button', 'btn small danger', 'Apply update');
      apply.type = 'button';
      apply.addEventListener('click', () => applyDockerProject(host, project.name, reload));
      projectActions.append(check, monitor, apply);
      card.append(projectActions);
      projectWrap.append(card);
    }
  }
  const projectContent = el('div');
  const bulkActions = el('div', 'modal-actions');
  const checkAll = el('button', 'btn', 'Check all projects');
  checkAll.type = 'button';
  checkAll.title = 'Pull images and compare all Compose projects without restarting containers';
  checkAll.addEventListener('click', () => checkAllDockerProjects(host, reload));
  const updateSelected = el('button', 'btn primary', 'Update selected');
  updateSelected.type = 'button';
  updateSelected.disabled = true;
  updateSelected.title = 'Pull and recreate only the selected Compose projects';
  const syncUpdateSelected = () => {
    updateSelected.disabled = selectedProjects.size === 0;
    updateSelected.textContent = selectedProjects.size ? 'Update selected (' + selectedProjects.size + ')' : 'Update selected';
  };
  updateSelected.addEventListener('click', () => updateSelectedDockerProjects(host, [...selectedProjects], reload));
  const updateAll = el('button', 'btn danger', 'Update all Compose projects');
  updateAll.type = 'button';
  updateAll.title = 'Pull images and recreate only projects whose image changed';
  updateAll.addEventListener('click', () => updateAllDockerProjects(host, reload));
  bulkActions.append(checkAll, updateSelected, updateAll);
  projectContent.append(bulkActions, projectWrap);
  panel.append(detailSection('Compose projects', projectContent));

  const containerWrap = el('div', 'scroll-list');
  const table = el('table');
  const head = el('tr');
  for (const label of ['Name', 'Project / service', 'Image', 'State', 'Health', 'Ports', '']) head.append(el('th', '', label));
  table.append(head);
  for (const container of containers) {
    const row = el('tr');
    const actionsTd = el('td');
    const monitor = actionButton('Monitor', () => showMonitorPreset({
      name: container.name + ' — container',
      type: 'docker.container',
      target: container.name,
      interval_seconds: 300,
      repeat_minutes: 60,
      cooldown_minutes: 15,
      enabled: true,
      assignments: [{ scope: 'host', target: host.id }],
    }));
    actionsTd.append(monitor);
    row.append(
      el('td', '', container.name),
      el('td', '', (container.project || '—') + (container.service ? ' / ' + container.service : '')),
      el('td', '', container.image),
      el('td', '', container.state + (container.status ? ' · ' + container.status : '')),
      el('td', '', container.health || '—'),
      el('td', '', container.ports || '—'),
      actionsTd,
    );
    table.append(row);
  }
  if (containers.length === 0) {
    containerWrap.append(el('div', '', 'No containers cached.'));
  } else {
    containerWrap.append(table);
  }
  panel.append(detailSection('Containers', containerWrap));

  const actions = el('div', 'modal-actions');
  const refresh = el('button', 'btn primary', 'Collect Docker inventory');
  refresh.type = 'button';
  refresh.addEventListener('click', async () => {
    try {
      const password = await passwordFor(host);
      await requestWithSudo(host, '/api/v1/hosts/' + encodeURIComponent(host.id) + '/docker/list',
        (sudoPassword) => ({ password, sudo_password: sudoPassword }), { method: 'POST' });
      toast('Docker inventory updated', 'ok');
      await reload();
    } catch (error) {
      if (error.message !== 'cancelled') toast(error.message, 'error');
    }
  });
  actions.append(refresh);
  panel.append(actions);
}

async function showHostDetails(host, initialTab = 'overview') {
  const body = el('div', 'modal-body');
  const tabs = el('div', 'tabs');
  const panels = el('div');
  const buttons = new Map();
  const panelNodes = new Map();
  let active = ['overview', 'system', 'services', 'containers'].includes(initialTab) ? initialTab : 'overview';
  let metricsDays = 30;
  for (const [id, label] of [['overview', 'Overview'], ['system', 'System'], ['services', 'Services'], ['containers', 'Containers']]) {
    const button = el('button', 'tab', label);
    button.type = 'button';
    button.addEventListener('click', () => {
      active = id;
      for (const [key, node] of buttons) node.classList.toggle('active', key === id);
      for (const [key, node] of panelNodes) node.classList.toggle('hidden', key !== id);
    });
    tabs.append(button);
    buttons.set(id, button);
    const panel = el('div', 'hidden');
    panels.append(panel);
    panelNodes.set(id, panel);
  }
  body.append(tabs, panels);
  openModal('Host — ' + host.name, body, null, 'wide');
  let data = null;
  const reload = async () => {
    data = await api('/api/v1/hosts/' + encodeURIComponent(host.id) + '/details?metrics_days=' + metricsDays);
    renderOverviewPanel(panelNodes.get('overview'), data, host);
    renderSystemPanel(panelNodes.get('system'), data, host, reload, async (days) => {
      metricsDays = days;
      await reload();
    });
    renderContainersPanel(panelNodes.get('containers'), data, host, reload);
    renderServicesPanel(panelNodes.get('services'), data, host, reload);
    for (const [key, node] of buttons) node.classList.toggle('active', key === active);
    for (const [key, node] of panelNodes) node.classList.toggle('hidden', key !== active);
  };
  try {
    await reload();
  } catch (error) {
    panelNodes.get(active).append(el('p', 'auth-message', error.message));
    panelNodes.get(active).classList.remove('hidden');
  }
}

async function showSettingsModal() {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Fleet defaults. Host-level overrides for collection and service-baseline settings are available from the host details view; backup settings are fleet-wide.'));
  const grid = el('div', 'settings-grid');
  const enabled = selectField(grid, 'Collector', 'collector_enabled', [['1', 'Enabled'], ['0', 'Disabled']]);
  const metricsInterval = inputField(grid, 'Metrics interval', 'metrics_interval', '5m');
  const factsInterval = inputField(grid, 'Facts interval', 'facts_interval', '12h');
  const retention = inputField(grid, 'Metrics retention (days)', 'retention_days', '30', 'number');
  const eventsEnabled = selectField(grid, 'Event collection', 'events_enabled', [['1', 'Enabled'], ['0', 'Disabled']]);
  const eventsRetention = inputField(grid, 'Event retention (days)', 'events_retention_days', '30', 'number');
  const authWindow = inputField(grid, 'Auth-failure window (minutes)', 'auth_window_minutes', '10', 'number');
  const roots = inputField(grid, 'Docker scan roots', 'docker_roots', '/opt');
  const baselineAutoAdd = selectField(grid, 'Add new running services to baseline', 'baseline_auto_add', [['1', 'Enabled'], ['0', 'Disabled']]);
  body.append(grid);
  body.append(el('p', 'field-note', 'Service baseline monitoring, exclusions, and per-host overrides are managed from a host’s Services tab. This fleet setting only controls whether units newly observed running are added to each host baseline.'));
  body.append(el('p', 'muted', 'Backups are fleet-wide. Leave the directory blank to use the database directory. Only timestamped backups created by HIBP are pruned; lowering the count deletes older HIBP-created backups on the next backup.'));
  const backupGrid = el('div', 'settings-grid');
  const backupDir = inputField(backupGrid, 'Backup directory', 'backup_directory', '/var/lib/hibp/backups');
  const backupRetention = inputField(backupGrid, 'Backups to keep', 'backup_retention_count', '3', 'number');
  body.append(backupGrid);
  const actions = el('div', 'modal-actions');
  const reset = el('button', 'btn', 'Use built-in defaults');
  reset.type = 'button';
  const save = el('button', 'btn primary', 'Save fleet settings');
  save.type = 'button';
  actions.append(reset, save);
  body.append(actions);
  const close = openModal('Settings', body);
  try {
    const data = await api('/api/v1/settings');
    const settings = data.resolved || {};
    enabled.value = settings['collector.enabled'] || '1';
    metricsInterval.value = settings['collector.metrics_interval'] || '5m';
    factsInterval.value = settings['collector.facts_interval'] || '12h';
    retention.value = settings['metrics.retention_days'] || '30';
    eventsEnabled.value = settings['events.enabled'] || '1';
    eventsRetention.value = settings['events.retention_days'] || '30';
    authWindow.value = settings['events.auth_window_minutes'] || '10';
    roots.value = settings['docker.scan_roots'] || '/opt';
    baselineAutoAdd.value = settings['monitor.service_baseline.auto_add'] || '1';
    backupDir.value = settings['backup.directory'] || '';
    backupRetention.value = settings['backup.retention_count'] || '3';
  } catch (error) {
    toast(error.message, 'error');
  }
  save.addEventListener('click', async () => {
    try {
      await api('/api/v1/settings', {
        method: 'PUT',
        body: JSON.stringify({
          scope: 'fleet',
          settings: {
            'collector.enabled': enabled.value,
            'collector.metrics_interval': metricsInterval.value.trim(),
            'collector.facts_interval': factsInterval.value.trim(),
            'metrics.retention_days': retention.value.trim(),
            'events.enabled': eventsEnabled.value,
            'events.retention_days': eventsRetention.value.trim(),
            'events.auth_window_minutes': authWindow.value.trim(),
            'docker.scan_roots': roots.value.trim(),
            'monitor.service_baseline.auto_add': baselineAutoAdd.value,
            'backup.directory': backupDir.value.trim(),
            'backup.retention_count': backupRetention.value.trim(),
          },
        }),
      });
      close();
      toast('Fleet settings saved', 'ok');
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  reset.addEventListener('click', async () => {
    try {
      await api('/api/v1/settings', {
        method: 'PUT',
        body: JSON.stringify({
          scope: 'fleet',
          settings: {
            'collector.enabled': '', 'collector.metrics_interval': '', 'collector.facts_interval': '',
            'metrics.retention_days': '', 'events.enabled': '', 'events.retention_days': '',
            'events.auth_window_minutes': '', 'docker.scan_roots': '',
            'monitor.service_baseline.auto_add': '',
            'backup.directory': '', 'backup.retention_count': '',
          },
        }),
      });
      close();
      toast('Fleet settings reset to built-in defaults', 'ok');
    } catch (error) {
      toast(error.message, 'error');
    }
  });
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

function openModal(title, content, onClose, sizeClass = '') {
  const root = $('modal-root');
  const backdrop = el('div', 'modal-backdrop');
  const modal = el('div', 'modal' + (sizeClass ? ' ' + sizeClass : ''));
  const head = el('div', 'modal-head');
  const close = el('button', 'modal-close', '×');
  close.type = 'button';
  head.append(el('div', 'modal-title', title), close);
  modal.append(head, content);
  backdrop.append(modal);
  root.append(backdrop);
  let closed = false;
  const closeFn = () => {
    if (closed) return;
    closed = true;
    backdrop.remove();
    const index = modalStack.findIndex((entry) => entry.close === closeFn);
    if (index >= 0) modalStack.splice(index, 1);
    if (onClose) onClose();
  };
  modalStack.push({ close: closeFn });
  close.addEventListener('click', closeFn);
  backdrop.addEventListener('click', (event) => { if (event.target === backdrop) closeFn(); });
  return closeFn;
}

async function showAgentTokenModal(host) {
  if (!confirm('Create or rotate the agent token for ' + host.name + '? The previous token will stop working immediately.')) return;
  try {
    const result = await api('/api/v1/hosts/' + encodeURIComponent(host.id) + '/agent', { method: 'POST', body: '{}' });
    const body = el('div', 'modal-body');
    body.append(el('p', 'muted', 'This token is shown once. Store it in the agent configuration on the target. It is not recoverable from the database.'));
    const pre = el('pre', 'key-box', result.token || '');
    pre.style.whiteSpace = 'pre-wrap';
    body.append(pre);
    body.append(el('p', 'field-note', 'Agent endpoint: https://<hibp-host>:<port>/api/v1/agent/v1/. The agent sends heartbeat, snapshot, and events.'));
    const actions = el('div', 'modal-actions');
    const close = el('button', 'btn primary', 'Close');
    close.type = 'button';
    actions.append(close);
    body.append(actions);
    const closeFn = openModal('Agent token — ' + host.name, body, null, 'wide');
    close.addEventListener('click', closeFn);
    await loadAll();
  } catch (error) {
    toast(error.message, 'error');
  }
}

function showAddHostModal(host = null, prefill = null) {
  // A click listener must never leak its Event into the edit path.
  if (host && !host.id) host = null;
  const editing = Boolean(host);
  const source = host || prefill || {};
  const form = el('form', 'modal-body');
  const name = inputField(form, 'Name', 'name', 'web01');
  const address = inputField(form, 'Address', 'address', '10.0.0.10');
  const row = el('div', 'form-row');
  const port = inputField(row, 'Port', 'port', '22', 'number');
  const username = inputField(row, 'Username', 'username', 'ubuntu');
  form.append(row);
  const authRow = el('div', 'form-row');
  const authType = selectField(authRow, 'Auth type', 'auth_type', [['key', 'SSH key file'], ['password', 'Password (manual fallback)'], ['agent', 'HIBP agent (monitoring only)']]);
  const keyPath = keyPathField(authRow, source.key_path || '', source.identity_files || []);
  form.append(authRow);
  const aptRow = el('div', 'form-row');
  const aptMode = selectField(aptRow, 'APT upgrade mode', 'apt_upgrade_mode', [
    ['safe', 'Safe upgrade — keeps held-back packages'],
    ['full', 'Full upgrade — may install/remove dependencies'],
  ]);
  form.append(aptRow);
  form.append(el('p', 'field-note', 'APT hosts only. Full upgrade uses apt-get full-upgrade and can install or remove packages. Review the patch preview before applying. Full mode requires an updated helper and sudoers rule on the target.'));
  const jump = source.proxy_jump || {};
  const jumpRow = el('div', 'form-row');
  const jumpAddress = inputField(jumpRow, 'Proxy jump host (optional)', 'proxy_jump_address', 'jump.example.com');
  const jumpPort = inputField(jumpRow, 'Proxy jump port', 'proxy_jump_port', '22', 'number');
  form.append(jumpRow);
  const jumpRow2 = el('div', 'form-row');
  const jumpUsername = inputField(jumpRow2, 'Proxy jump username', 'proxy_jump_username', 'ubuntu');
  const jumpKeyPath = keyPathField(jumpRow2, jump.key_path || '', [], {
    label: 'Proxy jump key path (optional)',
    name: 'proxy_jump_key_path',
    placeholder: 'Defaults to the host key',
  });
  form.append(jumpRow2);
  form.append(el('p', 'field-note', 'Optional single SSH jump hop. The jump host key is trusted separately. HIBP uses the jump key path when set; otherwise it uses the host key or the manual password.'));
  const groupRow = el('div', 'form-row');
  const group = inputField(groupRow, 'Group', 'group_name', 'web-prod');
  const tags = inputField(groupRow, 'Tags', 'tags', 'web,prod');
  form.append(groupRow);
  const cmdb = inputField(form, 'CMDB CI ID', 'cmdb_ci_id', 'CI-123');

  name.value = source.name || source.alias || '';
  address.value = source.address || source.hostname || '';
  port.value = String(source.port || 22);
  username.value = source.username || source.user || '';
  authType.value = source.auth_type || 'key';
  aptMode.value = source.apt_upgrade_mode || 'safe';
  jumpAddress.value = jump.address || '';
  jumpPort.value = String(jump.port || 22);
  jumpUsername.value = jump.username || jump.user || '';
  jumpKeyPath.value = jump.key_path || '';
  group.value = source.group_name || '';
  tags.value = source.tags || (prefill ? 'ssh-config' : '');
  cmdb.value = source.cmdb_ci_id || '';

  const actions = el('div', 'modal-actions');
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const save = el('button', 'btn primary', editing ? 'Save changes' : 'Add host');
  save.type = 'submit';
  actions.append(cancel, save);
  form.append(actions);
  const close = openModal(editing ? 'Edit host — ' + host.name : prefill ? 'Add host from SSH config' : 'Add host', form);
  cancel.addEventListener('click', close);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {
      name: name.value.trim(), address: address.value.trim(), port: Number(port.value || 22),
      username: username.value.trim(), auth_type: authType.value, key_path: keyPath.value.trim(),
      apt_upgrade_mode: aptMode.value,
      proxy_jump_address: jumpAddress.value.trim(), proxy_jump_port: Number(jumpPort.value || 22),
      proxy_jump_username: jumpUsername.value.trim(), proxy_jump_key_path: jumpKeyPath.value.trim(),
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

async function showSSHConfigModal() {
  const body = el('div', 'modal-body');
  const pathLine = el('p', 'muted', 'Reading local SSH config…');
  const list = el('div', 'file-list');
  body.append(pathLine, list);
  body.append(el('p', 'muted', 'HIBP always uses the selected key per connection (IdentitiesOnly behavior) and never forwards an SSH agent. Multi-hop ProxyJump chains are shown but not imported.'));
  const actions = el('div', 'modal-actions');
  const closeButton = el('button', 'btn', 'Close');
  closeButton.type = 'button';
  actions.append(closeButton);
  body.append(actions);
  const close = openModal('SSH config', body);
  closeButton.addEventListener('click', close);
  try {
    const result = await api('/api/v1/ssh/config');
    pathLine.textContent = result.path + (result.exists ? '' : ' (not found)');
    list.replaceChildren();
    if (!result.exists) {
      list.append(el('div', 'empty-state', 'No SSH config file found.'));
      return;
    }
    if (!result.hosts || result.hosts.length === 0) {
      list.append(el('div', 'empty-state', 'No concrete host entries found. Wildcard-only blocks are skipped.'));
      return;
    }
    for (const host of result.hosts) {
      const row = el('div', 'file-row');
      const entry = el('div', 'ssh-config-entry');
      const keys = (host.identity_files && host.identity_files.length ? host.identity_files : (host.key_path ? [host.key_path] : []))
        .filter((key) => key && !/\.pub$/i.test(key));
      entry.append(
        el('div', 'file-name', host.alias),
        el('div', 'file-meta', (host.user ? host.user + '@' : '') + host.hostname + ':' + host.port),
      );
      if (keys.length) {
        const keyList = el('div', 'ssh-key-list');
        for (const key of keys) keyList.append(el('div', 'file-meta', '🔑 ' + key));
        entry.append(keyList);
      } else {
        entry.append(el('div', 'file-meta', 'no key candidate'));
      }
      if (host.proxy_jump) {
        const jump = host.proxy_jump;
        entry.append(el('div', 'file-meta', '↪ ProxyJump: ' + (jump.user ? jump.user + '@' : '') + jump.address + ':' + (jump.port || 22)));
      } else if (host.proxy_jump_raw) {
        entry.append(el('div', 'file-meta', '↪ ProxyJump chain not imported: ' + host.proxy_jump_raw));
      }
      const use = el('button', 'btn small', 'Use');
      use.type = 'button';
      use.addEventListener('click', () => {
        close();
        showAddHostModal(null, host);
      });
      row.append(entry, use);
      list.append(row);
    }
  } catch (error) {
    pathLine.textContent = error.message;
  }
}

function keyPathField(parent, value, configuredKeys = [], options = {}) {
  const wrapper = el('label', 'field', options.label || 'Key path');
  const row = el('div', 'input-with-button');
  const input = el('input');
  input.name = options.name || 'key_path';
  input.type = 'text';
  input.placeholder = options.placeholder || '/home/ops/.ssh/id_ed25519';
  input.autocomplete = 'off';
  input.spellcheck = false;
  const keys = [...new Set(configuredKeys.filter((key) => key && !/\.pub$/i.test(key)))];
  input.value = value || keys[0] || '';
  const browse = el('button', 'btn small', 'Browse');
  browse.type = 'button';
  browse.addEventListener('click', () => showKeyBrowser((selected) => { input.value = selected; }));
  row.append(input, browse);
  wrapper.append(row);
  if (keys.length > 1) {
    const choices = el('div', 'key-choices');
    choices.append(el('div', 'muted', 'Configured keys'));
    for (const key of keys) {
      const choice = el('button', 'btn small', key.split('/').pop());
      choice.type = 'button';
      choice.title = key;
      choice.addEventListener('click', () => {
        input.value = key;
        input.focus();
      });
      choices.append(choice);
    }
    wrapper.append(choices);
  }
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

function showCMDBImportModal() {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Read-only import from a cmdb-lite export or any CSV/JSON host inventory. Preview is always shown before commit. HIBP never writes back to the CMDB.'));
  const file = el('input');
  file.type = 'file';
  file.accept = '.csv,.json,.txt,text/csv,application/json,text/plain';
  body.append(file);
  const textarea = el('textarea');
  textarea.placeholder = 'name,address,port,username,auth_type,key_path,group,tags,cmdb_ci_id\nweb01,10.0.0.10,22,ubuntu,key,/home/ops/.ssh/id_ed25519,prod,"web,prod",CI-123';
  body.append(textarea);
  const options = el('div', 'form-row');
  const format = selectField(options, 'Format', 'format', [['auto', 'Auto detect'], ['csv', 'CSV'], ['json', 'JSON']]);
  const mode = selectField(options, 'Existing hosts', 'mode', [['merge', 'Merge non-empty fields'], ['overwrite', 'Overwrite supplied fields']]);
  body.append(options);
  const defaults = el('div', 'form-row');
  const defaultUsername = inputField(defaults, 'Default SSH username (optional)', 'default_username', 'ubuntu');
  const defaultKeyPath = inputField(defaults, 'Default key path (optional)', 'default_key_path', '/home/ops/.ssh/id_ed25519');
  body.append(defaults);
  const modeNote = el('p', 'field-note');
  body.append(modeNote);
  const syncModeNote = () => {
    modeNote.textContent = mode.value === 'overwrite'
      ? 'Overwrite updates identity and inventory fields. Empty supplied group, tags, OS family, or OS version clears those fields. SSH auth fields are preserved unless the import supplies them.'
      : 'Merge updates only non-empty inventory fields. Existing SSH auth, facts, host keys, and optional fields are preserved when the import omits them.';
  };
  mode.addEventListener('change', syncModeNote);
  syncModeNote();
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
  const close = openModal('Import CMDB inventory', body, null, 'wide');
  cancel.addEventListener('click', close);
  file.addEventListener('change', async () => {
    const selected = file.files && file.files[0];
    if (selected) textarea.value = await selected.text();
  });
  const payload = (commit) => ({
    data: textarea.value,
    format: format.value,
    mode: mode.value,
    commit,
    default_username: defaultUsername.value.trim(),
    default_key_path: defaultKeyPath.value.trim(),
  });
  const renderPreview = (result) => {
    preview.replaceChildren();
    const summary = el('p', 'muted', result.format.toUpperCase() + ' · ' + result.mode + ' · '
      + result.rows.length + ' rows · ' + result.created + ' create · ' + result.updated + ' update'
      + (result.skipped ? ' · ' + result.skipped + ' skipped' : ''));
    preview.append(summary);
    if (result.problems && result.problems.length) {
      const problems = el('pre', 'key-box', result.problems.join('\n'));
      problems.style.maxHeight = '110px';
      problems.style.overflow = 'auto';
      preview.append(problems);
    }
    const table = el('table');
    const head = el('tr');
    for (const label of ['Row', 'Action', 'Name', 'Address', 'Port', 'User', 'Matched', 'Error']) head.append(el('th', '', label));
    table.append(head);
    for (const row of result.rows || []) {
      const tr = el('tr');
      const actionTd = el('td');
      const cls = row.action === 'create' ? 'green' : row.action === 'update' ? 'amber' : 'red';
      actionTd.append(el('span', 'badge ' + cls, row.action));
      tr.append(
        el('td', '', row.row),
        actionTd,
        el('td', '', row.name || '—'),
        el('td', '', row.address || '—'),
        el('td', '', row.port || '—'),
        el('td', '', row.username || '—'),
        el('td', '', row.matched_by || 'new'),
        el('td', '', row.error || ''),
      );
      table.append(tr);
    }
    preview.append(table);
    preview.classList.remove('hidden');
    commitButton.disabled = !(result.rows || []).some((row) => row.action === 'create' || row.action === 'update');
  };
  previewButton.addEventListener('click', async () => {
    try {
      const result = await api('/api/v1/cmdb/import', { method: 'POST', body: JSON.stringify(payload(false)) });
      renderPreview(result);
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  commitButton.addEventListener('click', async () => {
    try {
      const result = await api('/api/v1/cmdb/import', { method: 'POST', body: JSON.stringify(payload(true)) });
      close();
      toast('CMDB import: ' + result.created + ' created, ' + result.updated + ' updated, ' + result.skipped + ' skipped', 'ok');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
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
      commitButton.disabled = !(result.rows || []).some((row) => !row.error);
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

function updateMFAState(data) {
  state.auth.user = state.auth.user || {};
  state.auth.user.totp_enabled = Boolean(data.totp_enabled);
  state.auth.user.passkey_count = Array.isArray(data.passkeys)
    ? data.passkeys.length
    : Number(data.passkey_count || 0);
  state.auth.user.mfa_enabled = Boolean(data.totp_enabled) || state.auth.user.passkey_count > 0;
  updateUserDisplay();
}

async function showAccountSecurityModal() {
  if (state.status.demo) {
    const demoBody = el('div', 'modal-body');
    demoBody.append(el('p', 'preview-warning', 'This is a shared demo account. Password, TOTP, and passkey changes are disabled so one visitor cannot lock out everyone else.'));
    demoBody.append(el('p', 'muted', 'The demo login is guest / guest with the TOTP secret shown on the sign-in page. Passkeys are disabled in the demo.'));
    const demoActions = el('div', 'modal-actions');
    const demoClose = el('button', 'btn', 'Close');
    demoClose.type = 'button';
    demoActions.append(demoClose);
    demoBody.append(demoActions);
    const demoModal = openModal('Account security — demo', demoBody);
    demoClose.addEventListener('click', demoModal);
    return;
  }
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'HIBP requires at least one second factor. Removing the last configured factor is blocked so the account cannot be locked out of MFA.'));
  const summary = el('div', 'detail-card');
  const totpCard = el('div', 'detail-card');
  const passkeyCard = el('div', 'detail-card');
  const setupArea = el('div', 'mfa-setup');
  body.append(summary, totpCard, passkeyCard, setupArea);
  const actions = el('div', 'modal-actions');
  const closeButton = el('button', 'btn', 'Close');
  closeButton.type = 'button';
  actions.append(closeButton);
  body.append(actions);
  const close = openModal('Account security', body);
  closeButton.addEventListener('click', close);

  const beginTOTPSetup = async () => {
    setupArea.replaceChildren();
    setupArea.append(el('p', 'muted', 'Starting authenticator setup…'));
    try {
      const setup = await api('/api/v1/auth/totp/begin', { method: 'POST' });
      const card = el('div', 'detail-card mfa-setup-card');
      card.append(el('h3', '', 'Scan this QR code'));
      const qr = el('img', 'mfa-qr');
      qr.src = setup.qr_png;
      qr.alt = 'Authenticator enrollment QR code';
      const secret = el('div', 'mono mfa-secret', String(setup.secret || '').replace(/(.{4})/g, '$1 ').trim());
      const form = el('form', 'mfa-form');
      const code = inputField(form, 'Authenticator code', 'account_totp_code', '123456');
      code.maxLength = 8;
      const submit = el('button', 'btn primary', 'Verify and enable');
      submit.type = 'submit';
      form.append(submit);
      card.append(qr, secret, form);
      setupArea.replaceChildren(card);
      code.focus();
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        try {
          await api('/api/v1/auth/totp/verify', { method: 'POST', body: JSON.stringify({ code: code.value.trim() }) });
          toast('Authenticator enabled', 'ok');
          setupArea.replaceChildren();
          await reload();
        } catch (error) {
          toast(error.message, 'error');
        }
      });
    } catch (error) {
      setupArea.replaceChildren();
      toast(error.message, 'error');
    }
  };

  const addPasskey = async () => {
    if (!passkeySupported()) {
      toast('This browser cannot create passkeys. Use a current browser over http://localhost or HTTPS.', 'error');
      return;
    }
    try {
      const options = await api('/api/v1/auth/passkey/register/begin', { method: 'POST' });
      const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey);
      const credential = await navigator.credentials.create({ publicKey });
      if (!credential || typeof credential.toJSON !== 'function') throw new Error('Passkey creation failed.');
      const entered = window.prompt('Name this passkey', 'Passkey') || 'Passkey';
      await api('/api/v1/auth/passkey/register/finish', {
        method: 'POST',
        body: JSON.stringify({
          ceremony_id: options.ceremony_id,
          credential: credential.toJSON(),
          name: entered.trim().slice(0, 64),
        }),
      });
      toast('Passkey added', 'ok');
      await reload();
    } catch (error) {
      toast(error.name === 'NotAllowedError' ? 'Passkey prompt was cancelled.' : error.message, 'error');
    }
  };

  const removeTOTP = async () => {
    if (!confirm('Remove the authenticator app from this account? Make sure you can sign in with a passkey first.')) return;
    try {
      await api('/api/v1/auth/totp', { method: 'DELETE' });
      toast('Authenticator removed', 'ok');
      await reload();
    } catch (error) {
      toast(error.message, 'error');
    }
  };

  const removePasskey = async (passkey) => {
    if (!confirm('Remove passkey "' + passkey.name + '"?')) return;
    try {
      await api('/api/v1/auth/passkeys/' + encodeURIComponent(passkey.id), { method: 'DELETE' });
      toast('Passkey removed', 'ok');
      await reload();
    } catch (error) {
      toast(error.message, 'error');
    }
  };

  const render = (data) => {
    const passkeys = data.passkeys || [];
    summary.replaceChildren();
    summary.append(el('h3', '', 'Signed in as ' + data.username));
    summary.append(el('p', 'muted', (data.mfa_enabled ? 'MFA is enabled.' : 'MFA is not configured.') +
      (data.totp_enabled ? ' Authenticator: enabled.' : ' Authenticator: not configured.') +
      ' Passkeys: ' + passkeys.length + '.'));

    totpCard.replaceChildren();
    totpCard.append(el('h3', '', 'Authenticator app (TOTP)'));
    totpCard.append(el('p', 'muted', data.totp_enabled
      ? 'A time-based authenticator is configured. Replacing it requires the new code before the old secret is discarded.'
      : 'Add a TOTP authenticator as a second factor.'));
    const totpActions = el('div', 'actions');
    totpActions.append(actionButton(data.totp_enabled ? 'Replace authenticator' : 'Set up authenticator', beginTOTPSetup));
    if (data.totp_enabled) {
      const remove = actionButton('Remove authenticator', removeTOTP, 'danger');
      remove.disabled = passkeys.length === 0;
      if (remove.disabled) remove.title = 'Add a passkey before removing the last MFA factor';
      totpActions.append(remove);
    }
    totpCard.append(totpActions);

    passkeyCard.replaceChildren();
    passkeyCard.append(el('h3', '', 'Passkeys'));
    const add = actionButton('Add passkey', addPasskey, 'primary');
    const webauthnAvailable = Boolean(state.auth.webauthn_available ?? state.auth.webauthnAvailable);
    add.disabled = !webauthnAvailable;
    if (add.disabled) add.title = 'Open HIBP via http://localhost:<port> in a passkey-capable browser';
    passkeyCard.append(add);
    if (!passkeys.length) {
      passkeyCard.append(el('p', 'muted', 'No passkeys are registered.'));
    } else {
      const list = el('div', 'mfa-list');
      for (const passkey of passkeys) {
        const item = el('div', 'mfa-factor');
        const info = el('div');
        info.append(el('div', 'host-name', passkey.name || 'Passkey'));
        info.append(el('div', 'muted', 'Added ' + (passkey.created_at ? new Date(passkey.created_at).toLocaleString() : 'unknown') +
          (passkey.last_used_at ? ' · last used ' + new Date(passkey.last_used_at).toLocaleString() : '')));
        const remove = actionButton('Remove', () => removePasskey(passkey), 'danger');
        remove.disabled = passkeys.length <= 1 && !data.totp_enabled;
        if (remove.disabled) remove.title = 'Configure an authenticator before removing the last MFA factor';
        item.append(info, remove);
        list.append(item);
      }
      passkeyCard.append(list);
    }
  };

  async function reload() {
    try {
      const data = await api('/api/v1/auth/mfa');
      updateMFAState(data);
      render(data);
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  await reload();
}

function showBackupModal() {
  const body = el('div', 'modal-body');
  body.append(el('p', 'muted', 'Creates a consistent encrypted copy plus the .meta sidecar. Leave the field blank to use the configured backup directory (Settings), which defaults to the database directory. Enter an existing directory for a timestamped hibp-YYYY-MM-DD-HHMMSS.bac file, or enter a new absolute file path.'));
  if (state.status.demo) body.append(el('p', 'preview-warning', 'Demo mode: backup is simulated. No file is written.'));
  const path = inputField(body, 'Backup directory or file path', 'path', 'Configured directory (blank) or /var/lib/hibp');
  body.append(el('p', 'field-note', 'The configured retention count is applied to timestamped HIBP backups in the destination directory. The .meta sidecar is required to open the backup. A backup in the same directory is not protection against disk loss; copy it off-host according to your policy.'));
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
  if (state.status.demo) body.append(el('p', 'preview-warning', 'Demo mode: restore is simulated. No file is written.'));
  const backupPath = inputField(body, 'Backup path', 'backup_path', '/var/lib/hibp/hibp-2026-11-10-030000.bac');
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

function applyTheme(theme, persist = true) {
  const next = theme === 'light' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  document.documentElement.style.colorScheme = next;
  const toggle = $('theme-toggle');
  if (toggle) {
    const label = next === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
    toggle.setAttribute('aria-label', label);
    toggle.title = label;
  }
  if (persist) {
    try { localStorage.setItem('hibp-theme', next); } catch (e) { /* storage can be unavailable */ }
  }
}

function bindTheme() {
  const toggle = $('theme-toggle');
  if (!toggle) return;
  applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark', false);
  toggle.addEventListener('click', () => {
    applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
  });
}

function bind() {
  bindTheme();
  $('setup-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    clearAuthMessage();
    const username = $('setup-username').value.trim();
    const password = $('setup-password').value;
    if (Array.from(password).length < 12) {
      showAuthMessage('Password must be at least 12 characters.');
      return;
    }
    if (password !== $('setup-confirm').value) {
      showAuthMessage('Passwords do not match.');
      return;
    }
    try {
      await api('/api/v1/auth/setup', { method: 'POST', body: JSON.stringify({ username, password }) });
      $('setup-password').value = '';
      $('setup-confirm').value = '';
      await showAuthScreen();
    } catch (error) {
      showAuthMessage(error.message);
    }
  });

  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    clearAuthMessage();
    try {
      await api('/api/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          username: $('login-username').value.trim(),
          password: $('login-password').value,
        }),
      });
      $('login-password').value = '';
      await showAuthScreen();
      if (!state.auth.authenticated && !state.auth.mfa_required && !state.auth.setup_required) {
        showAuthMessage('Login succeeded, but the browser did not keep the session cookie. Allow cookies for this site and use the same http:// or https:// address as HIBP_DEMO_PUBLIC_URL.');
      }
    } catch (error) {
      showAuthMessage(error.message);
    }
  });

  $('totp-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    clearAuthMessage();
    try {
      await api('/api/v1/auth/totp/verify', {
        method: 'POST',
        body: JSON.stringify({ code: $('totp-code').value.trim() }),
      });
      $('totp-code').value = '';
      await showAuthScreen();
      if (!state.auth.authenticated) {
        showAuthMessage('The authenticator code was accepted, but the browser did not keep the session cookie. Allow cookies for this site and use the same http:// or https:// address as HIBP_DEMO_PUBLIC_URL.');
      }
    } catch (error) {
      showAuthMessage(error.message);
    }
  });

  $('totp-enroll-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    clearAuthMessage();
    try {
      await api('/api/v1/auth/totp/verify', {
        method: 'POST',
        body: JSON.stringify({ code: $('totp-enroll-code').value.trim() }),
      });
      $('totp-enroll-code').value = '';
      state.totpSetup = null;
      state.auth.user = state.auth.user || {};
      state.auth.user.totp_enabled = true;
      state.auth.user.mfa_enabled = true;
      state.auth.mfa_enrollment_required = false;
      $('enroll-totp').classList.add('hidden');
      $('totp-status').classList.remove('hidden');
      $('enroll-continue').classList.remove('hidden');
      showAuthMessage('TOTP enabled.', true);
    } catch (error) {
      showAuthMessage(error.message);
    }
  });

  $('passkey-register').addEventListener('click', registerPasskey);
  $('passkey-login').addEventListener('click', loginWithPasskey);
  $('demo-fill').addEventListener('click', demoLogin);
  $('mfa-back').addEventListener('click', async () => {
    await api('/api/v1/auth/logout', { method: 'POST', body: '{}' }).catch(() => {});
    setDemoSession('');
    state.totpSetup = null;
    await showAuthScreen();
  });
  $('enroll-continue').addEventListener('click', enterApp);
  $('enroll-logout').addEventListener('click', signOut);
  $('sign-out').addEventListener('click', signOut);
  $('account-security').addEventListener('click', showAccountSecurityModal);

  for (const button of document.querySelectorAll('.nav-item[data-view]')) {
    button.addEventListener('click', () => setView(button.dataset.view));
  }
  $('top-refresh').addEventListener('click', () => loadAll({ force: true }));
  $('refresh-button').addEventListener('click', () => loadAll({ force: true }));
  $('activity-toggle').addEventListener('click', () => {
    if (!jobDockState.open && !(state.jobs || []).length) {
      toast('No operations yet');
      return;
    }
    jobDockState.open = !jobDockState.open;
    if (jobDockState.open) jobDockState.expanded = true;
    renderJobs();
  });
  $('job-dock-minimize').addEventListener('click', () => {
    jobDockState.expanded = !jobDockState.expanded;
    renderJobs();
  });
  $('deploy-package').addEventListener('click', openDeployPackageFlow);
  $('fleet-deploy-package').addEventListener('click', openDeployPackageFlow);
  $('auto-refresh-toggle').checked = autoRefreshState.enabled;
  $('auto-refresh-toggle').addEventListener('change', (event) => setAutoRefresh(event.target.checked));
  window.setInterval(renderOperationBar, 1000);
  $('top-add-host').addEventListener('click', () => showAddHostModal());
  $('empty-add').addEventListener('click', () => showAddHostModal());
  $('import-button').addEventListener('click', showImportModal);
  $('table-import').addEventListener('click', showImportModal);
  $('hosts-import').addEventListener('click', showImportModal);
  $('table-cmdb').addEventListener('click', showCMDBImportModal);
  $('hosts-cmdb').addEventListener('click', showCMDBImportModal);
  $('table-ssh-config').addEventListener('click', showSSHConfigModal);
  $('hosts-ssh-config').addEventListener('click', showSSHConfigModal);
  $('table-update-helpers').addEventListener('click', () => fleetUpdateHelpers());
  $('fleet-update-helpers').addEventListener('click', () => fleetUpdateHelpers());
  $('table-update-selected').addEventListener('click', () => fleetUpdateHelpers(selectedHosts()));
  $('fleet-update-selected').addEventListener('click', () => fleetUpdateHelpers(selectedHosts()));
  $('table-facts-selected').addEventListener('click', () => fleetCollectFacts(selectedHosts()));
  $('fleet-facts-selected').addEventListener('click', () => fleetCollectFacts(selectedHosts()));
  $('table-runbook-selected').addEventListener('click', () => showRunbookModal(selectedHosts()));
  $('fleet-runbook-selected').addEventListener('click', () => showRunbookModal(selectedHosts()));
  $('table-patch-selected').addEventListener('click', () => showFleetPatchModal(selectedHosts()));
  $('fleet-patch-selected').addEventListener('click', () => showFleetPatchModal(selectedHosts()));
  $('table-cleanup-selected').addEventListener('click', () => showFleetCleanupModal(selectedHosts()));
  $('fleet-cleanup-selected').addEventListener('click', () => showFleetCleanupModal(selectedHosts()));
  $('table-reboot-selected').addEventListener('click', () => showFleetRebootModal(selectedHosts()));
  $('fleet-reboot-selected').addEventListener('click', () => showFleetRebootModal(selectedHosts()));
  for (const id of ['hosts-select-all', 'hosts-select-all-full']) {
    $(id).addEventListener('change', (event) => setAllHostSelection(event.target.checked));
  }
  $('open-settings').addEventListener('click', showSettingsModal);
  $('monitor-add').addEventListener('click', () => showMonitorModal());
  $('monitor-add-web').addEventListener('click', () => showMonitorModal(null, {
    type: 'http',
    interval_seconds: 60,
    warning: 0,
    critical: 0,
    repeat_minutes: 60,
    cooldown_minutes: 15,
    assignments: [],
  }));
  $('monitor-notifications').addEventListener('click', showSMTPModal);
  $('monitor-map-group').value = state.monitorMapGroup;
  $('monitor-map-group').addEventListener('change', (event) => {
    state.monitorMapGroup = event.target.value;
    renderMonitoring();
  });
  $('monitors-select-all').addEventListener('change', (event) => setAllMonitorSelection(event.target.checked));
  $('monitor-bulk-edit').addEventListener('click', () => showMonitorBulkEditModal(selectedMonitors()));
  $('monitor-check-selected').addEventListener('click', () => checkSelectedMonitors(selectedMonitors()));
  $('monitor-enable-selected').addEventListener('click', () => setSelectedMonitorsEnabled(true));
  $('monitor-disable-selected').addEventListener('click', () => setSelectedMonitorsEnabled(false));
  for (const header of document.querySelectorAll('#view-monitoring th[data-sort]')) {
    header.tabIndex = 0;
    header.addEventListener('click', () => setMonitorSort(header.dataset.sort));
    header.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      setMonitorSort(header.dataset.sort);
    });
  }
  $('schedule-add').addEventListener('click', () => showScheduleModal());
  $('backup-button').addEventListener('click', showBackupModal);
  $('restore-button').addEventListener('click', showRestoreModal);
  $('verify-audit').addEventListener('click', verifyAudit);
  $('audit-verify').addEventListener('click', verifyAudit);
}

async function init() {
  bind();
  await showAuthScreen();
}

init();
