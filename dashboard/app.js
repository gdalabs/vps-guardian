const API = '';  // same origin
let currentTab = 'logins';
let autoRefreshTimer = null;

// --- Theme ---
function getPreferredTheme() {
  const saved = localStorage.getItem('guardian-theme');
  if (saved) return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme === 'dark' ? 'dark' : '');
  localStorage.setItem('guardian-theme', theme);
  const icon = document.getElementById('theme-icon');
  if (icon) icon.innerHTML = theme === 'dark' ? '&#9790;' : '&#9788;';
}

applyTheme(getPreferredTheme());

document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', () => {
      const current = localStorage.getItem('guardian-theme') || getPreferredTheme();
      applyTheme(current === 'dark' ? 'light' : 'dark');
    });
  }
});

// --- QR Code ---
function toggleQR() {
  const overlay = document.getElementById('qr-overlay');
  const isActive = overlay.classList.toggle('active');
  if (isActive) {
    const url = window.location.href;
    document.getElementById('qr-img').src = `/api/qr?url=${encodeURIComponent(url)}`;
    document.getElementById('qr-url').textContent = url;
  }
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.getElementById('qr-overlay').classList.remove('active');
  }
});

// --- Utilities ---
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

function getHours() {
  return parseInt($('#time-range').value) || 24;
}

async function api(path, params = {}) {
  const qs = new URLSearchParams({ hours: getHours(), ...params });
  const res = await fetch(`${API}/api/${path}?${qs}`);
  return res.json();
}

function fmtTime(ts) {
  if (!ts) return '-';
  // Normalize: if no timezone info, assume UTC
  let s = ts;
  if (!/Z|[+-]\d{2}:\d{2}$/.test(s)) s += 'Z';
  const d = new Date(s);
  if (isNaN(d.getTime())) return ts;  // fallback to raw string
  return d.toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', hour12: false,
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function fmtMB(mb) {
  if (mb >= 1024) return (mb / 1024).toFixed(1) + ' GB';
  return mb + ' MB';
}

function pctColor(pct) {
  if (pct > 85) return 'var(--red)';
  if (pct > 60) return 'var(--yellow)';
  return 'var(--green)';
}

// --- Clock ---
function updateClock() {
  const now = new Date();
  $('#clock').textContent = now.toLocaleString('ja-JP', {
    timeZone: 'Asia/Tokyo', hour12: false,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

// --- Stats Bar ---
async function loadStats() {
  const data = await api('stats');
  const set = (id, val, cls) => {
    const el = $(`#${id} .stat-value`);
    el.textContent = val.toLocaleString();
    el.className = 'stat-value ' + cls;
  };
  set('stat-logins', data.ssh_logins, data.ssh_logins > 0 ? 'ok' : '');
  set('stat-failed', data.ssh_failed, data.ssh_failed > 100 ? 'warning' : '');
  set('stat-attackers', data.unique_attackers, data.unique_attackers > 10 ? 'warning' : '');
  set('stat-unknown', data.unknown_ip_logins, data.unknown_ip_logins > 0 ? 'critical' : 'ok');
  set('stat-alerts', data.active_alerts, data.active_alerts > 0 ? 'critical' : 'ok');
  set('stat-hooks', data.hook_blocks, data.hook_blocks > 0 ? 'warning' : 'ok');
}

// --- Resources ---
async function loadResources() {
  const data = await api('resources/latest');
  const r = Array.isArray(data) ? data[0] : data;
  if (!r) return;

  const cpuPct = r.cpu_percent || 0;
  const memPct = r.mem_total_mb ? ((r.mem_used_mb / r.mem_total_mb) * 100) : 0;
  const diskPct = r.disk_total_gb ? ((r.disk_used_gb / r.disk_total_gb) * 100) : 0;
  const swapPct = r.swap_total_mb ? ((r.swap_used_mb / r.swap_total_mb) * 100) : 0;

  function setBar(id, pct, label) {
    const bar = $(`#${id}-bar`);
    const val = $(`#${id}-value`);
    bar.style.width = Math.min(pct, 100) + '%';
    bar.style.background = pctColor(pct);
    val.textContent = label;
  }

  setBar('cpu', cpuPct, cpuPct.toFixed(1) + '%');
  setBar('mem', memPct, `${fmtMB(r.mem_used_mb)} / ${fmtMB(r.mem_total_mb)} (${memPct.toFixed(0)}%)`);
  setBar('disk', diskPct, `${r.disk_used_gb} GB / ${r.disk_total_gb} GB (${diskPct.toFixed(0)}%)`);
  setBar('swap', swapPct, `${r.swap_used_mb} MB / ${r.swap_total_mb} MB`);
  $('#load-value').textContent = `${r.load_1} / ${r.load_5} / ${r.load_15} (1m / 5m / 15m)`;
}

// --- Services ---
async function loadServices() {
  const data = await api('services');
  const systemd = data.filter(s => s.service_type === 'systemd');
  const docker = data.filter(s => s.service_type === 'docker');
  const ports = data.filter(s => s.service_type === 'listening_port');

  $('#systemd-list').innerHTML = systemd.map(s => {
    const running = s.status === 'active' || s.status === 'running';
    return `<div class="svc-item">
      <span class="svc-dot ${running ? 'running' : 'stopped'}"></span>
      <span class="svc-name">${s.service_name}</span>
      <span class="svc-badge ${running ? 'localhost' : 'public'}">${s.status}</span>
    </div>`;
  }).join('') || '<div class="svc-item">No data</div>';

  $('#docker-list').innerHTML = docker.map(s => {
    const running = s.status === 'running';
    let detail = {};
    try { detail = JSON.parse(s.detail); } catch {}
    return `<div class="svc-item">
      <span class="svc-dot ${running ? 'running' : 'stopped'}"></span>
      <span class="svc-name" title="${detail.image || ''}">${s.service_name}</span>
      <span class="svc-badge ${running ? 'localhost' : 'public'}">${s.status}</span>
    </div>`;
  }).join('') || '<div class="svc-item">No containers</div>';

  $('#ports-list').innerHTML = ports.map(s => {
    let detail = {};
    try { detail = JSON.parse(s.detail); } catch {}
    const exposure = detail.exposure || s.status;
    return `<div class="svc-item">
      <span class="svc-dot ${exposure}"></span>
      <span class="svc-name">${s.service_name} (${detail.process || '?'})</span>
      <span class="svc-badge ${exposure}">${exposure}</span>
    </div>`;
  }).join('') || '<div class="svc-item">No ports</div>';
}

// --- Claude Code ---
async function loadClaude() {
  const data = await api('claude');
  if (!data.length) {
    $('#claude-list').innerHTML = '<div style="color:var(--text-dim);padding:8px">No active instances</div>';
    return;
  }
  $('#claude-list').innerHTML = `<table>
    <tr><th>Project</th><th>PID</th><th>User</th><th>TTY</th><th>Memory</th><th>CPU%</th><th>Started</th></tr>
    ${data.map(c => `<tr>
      <td><span class="claude-project">${c.project_name || c.work_dir || '-'}</span></td>
      <td>${c.pid}</td>
      <td>${c.username}</td>
      <td>${c.tty}</td>
      <td class="claude-mem">${c.mem_rss_kb ? (c.mem_rss_kb / 1024).toFixed(0) + ' MB' : '-'}</td>
      <td>${c.cpu_percent || '-'}</td>
      <td>${c.start_time || '-'}</td>
    </tr>`).join('')}
  </table>`;
}

// --- Access Log ---
async function loadAccess() {
  const container = $('#access-content');

  if (currentTab === 'logins') {
    const data = await api('access/ssh', { limit: 100 });
    const logins = data.filter(a => a.event_type === 'login');
    container.innerHTML = `<table>
      <tr><th>Time</th><th>IP</th><th>User</th><th>Method</th><th>Status</th></tr>
      ${logins.map(a => {
        let detail = {};
        try { detail = JSON.parse(a.detail); } catch {}
        const cls = a.is_whitelisted ? 'whitelisted' : 'unknown';
        return `<tr class="${cls}">
          <td>${fmtTime(a.timestamp)}</td>
          <td>${a.source_ip}</td>
          <td>${a.username}</td>
          <td>${detail.auth_method || '-'}</td>
          <td>${a.is_whitelisted ? 'Known' : '<strong style="color:var(--red)">UNKNOWN</strong>'}</td>
        </tr>`;
      }).join('')}
    </table>`;
  } else if (currentTab === 'failed') {
    const data = await api('access/failed/summary');
    container.innerHTML = `<table>
      <tr><th>Source IP</th><th>Attempts</th><th>First Seen</th><th>Last Seen</th></tr>
      ${data.map(a => `<tr>
        <td>${a.source_ip}</td>
        <td style="color:var(--red);font-weight:700">${a.count.toLocaleString()}</td>
        <td>${fmtTime(a.first_seen)}</td>
        <td>${fmtTime(a.last_seen)}</td>
      </tr>`).join('')}
    </table>`;
  } else if (currentTab === 'unknown') {
    const data = await api('access/unknown');
    container.innerHTML = data.length
      ? `<table>
          <tr><th>Time</th><th>IP</th><th>User</th><th>Detail</th></tr>
          ${data.map(a => `<tr class="unknown">
            <td>${fmtTime(a.timestamp)}</td>
            <td style="color:var(--red);font-weight:700">${a.source_ip}</td>
            <td>${a.username}</td>
            <td>${a.detail || '-'}</td>
          </tr>`).join('')}
        </table>`
      : '<div style="color:var(--green);padding:20px;text-align:center;font-size:16px">No unknown IP logins detected</div>';
  } else if (currentTab === 'hooks') {
    const data = await api('hooks');
    container.innerHTML = data.length
      ? `<table>
          <tr><th>Time</th><th>Event</th><th>Detail</th></tr>
          ${data.map(a => {
            let detail = {};
            try { detail = JSON.parse(a.detail); } catch {}
            return `<tr>
              <td>${fmtTime(a.timestamp)}</td>
              <td style="color:var(--orange)">${a.event_type}</td>
              <td>${detail.reason || a.detail || '-'}</td>
            </tr>`;
          }).join('')}
        </table>`
      : '<div style="color:var(--green);padding:20px;text-align:center">No hook blocks recorded</div>';
  }
}

// --- API Cost ---
async function loadCost() {
  const [summary, daily, byProject] = await Promise.all([
    api('cost/summary'),
    api('cost', { days: 7, group: 'date' }),
    api('cost', { days: 30, group: 'project' }),
  ]);

  function fmtUSD(v) { return '$' + (v || 0).toFixed(2); }
  function fmtTokens(t) {
    if (!t) return '0';
    if (t >= 1_000_000) return (t / 1_000_000).toFixed(1) + 'M';
    if (t >= 1_000) return (t / 1_000).toFixed(0) + 'K';
    return t.toString();
  }

  // Summary cards
  $('#cost-summary').innerHTML = `
    <div class="cost-card">
      <div class="cost-amount accent">${fmtUSD(summary.today_cost)}</div>
      <div class="cost-label">Today</div>
    </div>
    <div class="cost-card">
      <div class="cost-amount">${fmtUSD(summary.week_cost)}</div>
      <div class="cost-label">This Week</div>
    </div>
    <div class="cost-card">
      <div class="cost-amount">${fmtUSD(summary.month_cost)}</div>
      <div class="cost-label">This Month</div>
    </div>
    <div class="cost-card">
      <div class="cost-amount">${fmtUSD(summary.total_cost)}</div>
      <div class="cost-label">All Time</div>
    </div>
    <div class="cost-card">
      <div class="cost-amount">${summary.total_messages?.toLocaleString() || 0}</div>
      <div class="cost-label">Messages</div>
    </div>
    <div class="cost-card">
      <div class="cost-amount">${fmtTokens(summary.total_output_tokens)}</div>
      <div class="cost-label">Output Tokens</div>
    </div>
  `;

  // Daily + project bars side by side
  const maxDaily = Math.max(...daily.map(d => d.cost_usd || 0), 0.01);
  const maxProj = Math.max(...byProject.map(d => d.cost_usd || 0), 0.01);

  const dailyBars = daily.slice(0, 7).map(d => `
    <div class="cost-bar-row">
      <span class="cost-bar-label">${d.date?.slice(5) || '-'}</span>
      <div class="cost-bar-track">
        <div class="cost-bar-fill" style="width:${((d.cost_usd || 0) / maxDaily * 100).toFixed(1)}%"></div>
      </div>
      <span class="cost-bar-value">${fmtUSD(d.cost_usd)}</span>
    </div>
  `).join('');

  const projBars = byProject.filter(d => (d.cost_usd || 0) > 0).slice(0, 10).map(d => `
    <div class="cost-bar-row">
      <span class="cost-bar-label">${d.project || '-'}</span>
      <div class="cost-bar-track">
        <div class="cost-bar-fill" style="width:${((d.cost_usd || 0) / maxProj * 100).toFixed(1)}%;background:var(--green)"></div>
      </div>
      <span class="cost-bar-value">${fmtUSD(d.cost_usd)}</span>
    </div>
  `).join('');

  $('#cost-detail').innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div><h3 style="margin-bottom:6px">Daily (7d)</h3>${dailyBars || '<div style="color:var(--text-dim)">No data</div>'}</div>
      <div><h3 style="margin-bottom:6px">By Project (30d)</h3>${projBars || '<div style="color:var(--text-dim)">No data</div>'}</div>
    </div>
  `;
}

// --- Alerts ---
async function loadAlerts() {
  const data = await api('alerts', { limit: 50 });
  if (!data.length) {
    $('#alerts-list').innerHTML = '<div style="color:var(--green);padding:12px;text-align:center">No alerts</div>';
    return;
  }
  $('#alerts-list').innerHTML = data.map(a => `
    <div class="alert-item ${a.severity}">
      <span class="alert-badge ${a.severity}">${a.severity}</span>
      <span class="alert-time">${fmtTime(a.timestamp)}</span>
      <span class="alert-msg">${a.message}</span>
    </div>
  `).join('');
}

// --- Security Posture ---
async function loadSecurity() {
  const services = await api('services');
  const checks = [];

  // SSH on port 22 — public exposure
  const sshPort = services.find(s => s.service_name === 'port:22');
  if (sshPort) {
    let detail = {};
    try { detail = JSON.parse(sshPort.detail); } catch {}
    checks.push({
      label: 'SSH (Port 22) is publicly accessible',
      status: detail.exposure === 'public' ? 'warn' : 'pass',
      note: detail.exposure === 'public' ? 'Consider Tailscale-only' : 'OK'
    });
  }

  // Check services
  const sshSvc = services.find(s => s.service_name === 'ssh' && s.service_type === 'systemd');
  const tailscaleSvc = services.find(s => s.service_name === 'tailscaled' && s.service_type === 'systemd');
  const dockerSvc = services.find(s => s.service_name === 'docker' && s.service_type === 'systemd');

  checks.push({
    label: 'SSH Service',
    status: sshSvc?.status === 'active' ? 'pass' : 'fail',
    note: sshSvc?.status || 'not found'
  });
  checks.push({
    label: 'Tailscale Service',
    status: tailscaleSvc?.status === 'active' ? 'pass' : 'fail',
    note: tailscaleSvc?.status || 'not found'
  });
  checks.push({
    label: 'Docker Service',
    status: dockerSvc?.status === 'active' ? 'pass' : 'fail',
    note: dockerSvc?.status || 'not found'
  });

  // Public port count
  const publicPorts = services.filter(s => {
    if (s.service_type !== 'listening_port') return false;
    try { return JSON.parse(s.detail).exposure === 'public'; } catch { return false; }
  });
  checks.push({
    label: `Public-facing ports: ${publicPorts.length}`,
    status: publicPorts.length <= 1 ? 'pass' : publicPorts.length <= 3 ? 'warn' : 'fail',
    note: publicPorts.map(p => p.service_name).join(', ') || 'none'
  });

  // Tailscale-only ports
  const tsPorts = services.filter(s => {
    if (s.service_type !== 'listening_port') return false;
    try { return JSON.parse(s.detail).exposure === 'tailscale'; } catch { return false; }
  });
  checks.push({
    label: `Tailscale-only ports: ${tsPorts.length}`,
    status: 'pass',
    note: tsPorts.map(p => p.service_name).join(', ')
  });

  // fail2ban
  const f2b = await api('fail2ban');
  const f2bSvc = services.find(s => s.service_name === 'fail2ban' && s.service_type === 'systemd');
  checks.push({
    label: 'fail2ban',
    status: f2bSvc?.status === 'active' ? 'pass' : 'fail',
    note: f2bSvc?.status === 'active'
      ? `Active — ${f2b.currently_banned} IPs banned (total: ${f2b.total_banned})`
      : 'NOT RUNNING'
  });

  // Unknown IP logins
  const stats = await api('stats');
  checks.push({
    label: 'Unknown IP SSH logins (all time)',
    status: stats.unknown_ip_logins === 0 ? 'pass' : 'fail',
    note: stats.unknown_ip_logins === 0 ? 'Clean' : `${stats.unknown_ip_logins} detected!`
  });

  const icons = { pass: '\u2705', fail: '\u274C', warn: '\u26A0\uFE0F' };
  $('#security-checklist').innerHTML = checks.map(c => `
    <div class="check-item ${c.status}">
      <span class="check-icon">${icons[c.status]}</span>
      <span style="flex:1">${c.label}</span>
      <span style="color:var(--text-dim);font-size:11px">${c.note}</span>
    </div>
  `).join('');
}

// --- Tab switching ---
$$('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    $$('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    currentTab = tab.dataset.tab;
    loadAccess();
  });
});

// --- Refresh All ---
async function refreshAll() {
  try {
    await Promise.all([
      loadStats(),
      loadResources(),
      loadServices(),
      loadClaude(),
      loadAccess(),
      loadCost(),
      loadAlerts(),
      loadSecurity(),
    ]);
    $('#status-dot').className = 'dot green';
  } catch (e) {
    console.error('Refresh error:', e);
    $('#status-dot').className = 'dot red';
  }
}

$('#time-range').addEventListener('change', refreshAll);

// --- Init ---
updateClock();
setInterval(updateClock, 1000);
refreshAll();
autoRefreshTimer = setInterval(refreshAll, 30000);  // Auto-refresh every 30s
