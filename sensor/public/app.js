// State variables
let currentSequence = 0;
let isFetching = false;
let selectedIp = null;
let pollTimer = null;

// DOM Elements
const errorBar = document.getElementById('error-bar');
const actionBar = document.getElementById('action-bar');
const actionMessage = document.getElementById('action-message');
const closeActionBtn = document.getElementById('close-action-btn');

const statsTotal = document.getElementById('stats-total');
const statsIps = document.getElementById('stats-ips');
const statsHigh = document.getElementById('stats-high');
const statsMedium = document.getElementById('stats-medium');
const statsLow = document.getElementById('stats-low');

const attackersTbody = document.getElementById('attackers-tbody');
const feedTbody = document.getElementById('feed-tbody');

const detailPanel = document.getElementById('detail-panel');
const detailEmpty = document.getElementById('detail-empty');
const detailIp = document.getElementById('detail-ip');
const detailBadge = document.getElementById('detail-badge');
const detailSummary = document.getElementById('detail-summary');
const detailTools = document.getElementById('detail-tools');
const detailUsernames = document.getElementById('detail-usernames');
const detailPasswords = document.getElementById('detail-passwords');
const detailPaths = document.getElementById('detail-paths');
const detailTimeline = document.getElementById('detail-timeline');

const showBansBtn = document.getElementById('show-bans-btn');
const closeBansBtn = document.getElementById('close-bans-btn');
const bansPanel = document.getElementById('bans-panel');
const bansTbody = document.getElementById('bans-tbody');

const banModal = document.getElementById('ban-modal');
const banTargetIp = document.getElementById('ban-target-ip');
const banReason = document.getElementById('ban-reason');
const banHours = document.getElementById('ban-hours');
const confirmBanBtn = document.getElementById('confirm-ban-btn');
const cancelBanBtn = document.getElementById('cancel-ban-btn');
let banIpToSubmit = null;

// Valid levels map to safe CSS classes
const BADGE_CLASSES = {
  High: 'badge-High',
  Medium: 'badge-Medium',
  Low: 'badge-Low',
  None: 'badge-None'
};

function getBadgeClass(level) {
  return BADGE_CLASSES[level] || 'badge-None';
}

function formatDate(isoString) {
  if (!isoString) return '';
  try {
    return new Date(isoString).toLocaleString();
  } catch (e) {
    return isoString;
  }
}

let csrfToken = '';

async function checkSession() {
  try {
    const res = await fetch('/api/session');
    if (!res.ok) {
      window.location.href = '/login.html';
      return;
    }
    const data = await res.json();
    csrfToken = data.csrf;
  } catch (err) {
    window.location.href = '/login.html';
  }
}

async function fetchJson(url, options = {}) {
  if (options.method === 'POST') {
    options.headers = options.headers || {};
    options.headers['X-CSRF-Token'] = csrfToken;
  }
  const res = await fetch(url, options);
  if (res.status === 401) {
    window.location.href = '/login.html';
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function renderStats(stats) {
  statsTotal.textContent = stats.total_events || 0;
  statsIps.textContent = stats.unique_ips || 0;
  statsHigh.textContent = stats.levels.High || 0;
  statsMedium.textContent = stats.levels.Medium || 0;
  statsLow.textContent = stats.levels.Low || 0;
}

function createTableCell(text, title = null) {
  const td = document.createElement('td');
  td.textContent = text;
  if (title) {
    td.setAttribute('title', title);
  }
  return td;
}

function renderAttackers(attackers) {
  attackersTbody.textContent = ''; // Fast clear (safe)
  
  if (!attackers || attackers.length === 0) {
    const tr = document.createElement('tr');
    tr.className = 'empty-state';
    const td = document.createElement('td');
    td.setAttribute('colspan', '6');
    td.textContent = 'No attackers yet.';
    tr.appendChild(td);
    attackersTbody.appendChild(tr);
    return;
  }

  attackers.forEach(a => {
    const tr = document.createElement('tr');
    tr.className = 'clickable-row';
    if (a.ip === selectedIp) {
      tr.classList.add('selected-row');
    }
    tr.addEventListener('click', () => selectAttacker(a.ip));

    const tdIp = createTableCell(a.ip);
    
    if (a.banned) {
      const bBadge = document.createElement('span');
      bBadge.className = 'badge badge-banned';
      bBadge.textContent = 'BANNED';
      bBadge.style.marginLeft = '5px';
      tdIp.appendChild(bBadge);
    }
    
    const tdLevel = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge ' + getBadgeClass(a.level);
    badge.textContent = a.level || 'None';
    tdLevel.appendChild(badge);

    const tdScore = createTableCell(a.score);
    const tdEvents = createTableCell(a.total_events);
    const tdSeen = createTableCell(formatDate(a.last_seen), a.last_seen);
    const tdSummary = createTableCell(a.summary);

    const tdAction = document.createElement('td');
    const actionBtn = document.createElement('button');
    if (a.banned) {
      actionBtn.textContent = 'Unban';
      actionBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        unbanIp(a.ip);
      });
    } else {
      actionBtn.textContent = 'Ban';
      actionBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        openBanModal(a.ip);
      });
    }
    tdAction.appendChild(actionBtn);

    tr.appendChild(tdIp);
    tr.appendChild(tdLevel);
    tr.appendChild(tdScore);
    tr.appendChild(tdEvents);
    tr.appendChild(tdSeen);
    tr.appendChild(tdSummary);
    tr.appendChild(tdAction);
    
    attackersTbody.appendChild(tr);
  });
}

function renderFeed(events) {
  feedTbody.textContent = '';
  
  if (!events || events.length === 0) {
    const tr = document.createElement('tr');
    tr.className = 'empty-state';
    const td = document.createElement('td');
    td.setAttribute('colspan', '6');
    td.textContent = 'No events yet.';
    tr.appendChild(td);
    feedTbody.appendChild(tr);
    return;
  }

  events.forEach(e => {
    const tr = document.createElement('tr');
    tr.appendChild(createTableCell(formatDate(e.timestamp), e.timestamp));
    tr.appendChild(createTableCell(e.source_ip));
    tr.appendChild(createTableCell(e.protocol));
    tr.appendChild(createTableCell(e.port));
    tr.appendChild(createTableCell(e.method || ''));
    
    let detail = e.path || '';
    if (e.username) detail += (detail ? ' ' : '') + `u:${e.username}`;
    if (e.password) detail += (detail ? ' ' : '') + `p:${e.password}`;
    tr.appendChild(createTableCell(detail));
    
    feedTbody.appendChild(tr);
  });
}

async function selectAttacker(ip) {
  if (selectedIp === ip) return;
  selectedIp = ip;
  
  // Update highlight visually before next polling cycle
  const rows = attackersTbody.querySelectorAll('tr');
  rows.forEach(r => {
    const rowIp = r.firstElementChild?.textContent;
    if (rowIp === ip) r.classList.add('selected-row');
    else r.classList.remove('selected-row');
  });

  await fetchSelectedAttackerDetails();
}

function renderList(container, items, formatFn) {
  container.textContent = '';
  if (!items || items.length === 0) {
    const li = document.createElement('li');
    li.textContent = '-';
    container.appendChild(li);
    return;
  }
  items.forEach(item => {
    const li = document.createElement('li');
    li.textContent = formatFn(item);
    container.appendChild(li);
  });
}

async function fetchSelectedAttackerDetails() {
  if (!selectedIp) {
    detailPanel.classList.add('hidden');
    detailEmpty.classList.remove('hidden');
    return;
  }

  // Validate IP format
  if (!/^[a-fA-F0-9.:]+$/.test(selectedIp)) {
    return;
  }

  try {
    const data = await fetchJson(`/api/attackers/${encodeURIComponent(selectedIp)}`);
    
    detailEmpty.classList.add('hidden');
    detailPanel.classList.remove('hidden');

    detailIp.textContent = selectedIp;
    
    const level = data.assessment?.level || 'None';
    detailBadge.textContent = level;
    detailBadge.className = 'badge ' + getBadgeClass(level);

    detailSummary.textContent = data.assessment?.summary || 'No data';
    detailTools.textContent = (data.assessment?.tool_hints || []).join(', ') || 'None';

    const attacksContainer = document.getElementById('detail-attacks');
    const attacksGroup = document.getElementById('detail-attacks-container');
    attacksContainer.textContent = '';
    const labels = data.assessment?.labels || [];
    
    if (labels.length > 0) {
      labels.forEach(lbl => {
        const span = document.createElement('span');
        span.className = 'badge';
        span.style.backgroundColor = '#3b82f6';
        span.style.color = '#fff';
        
        let displayTxt = lbl;
        if (lbl === 'port_scan') displayTxt = 'Port Scan';
        if (lbl === 'brute_force') displayTxt = 'Brute Force';
        if (lbl === 'web_probe') displayTxt = 'Web Probe';
        
        span.textContent = displayTxt;
        attacksContainer.appendChild(span);
      });
      attacksGroup.classList.remove('hidden');
    } else {
      attacksGroup.classList.add('hidden');
    }

    renderList(detailUsernames, data.profile?.top_usernames, x => `${x.username} (${x.count})`);
    renderList(detailPasswords, data.profile?.top_passwords, x => `${x.password} (${x.count})`);
    renderList(detailPaths, data.profile?.paths_probed, x => `${x.path} (${x.count})`);

    // Render Timeline
    detailTimeline.textContent = '';
    const timeline = data.timeline || [];
    if (timeline.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.setAttribute('colspan', '5');
      td.textContent = 'No events.';
      tr.appendChild(td);
      detailTimeline.appendChild(tr);
    } else {
      timeline.forEach(e => {
        const tr = document.createElement('tr');
        tr.appendChild(createTableCell(formatDate(e.timestamp), e.timestamp));
        tr.appendChild(createTableCell(e.protocol));
        tr.appendChild(createTableCell(e.port));
        tr.appendChild(createTableCell(e.method || ''));
        tr.appendChild(createTableCell(e.detail || ''));
        detailTimeline.appendChild(tr);
      });
    }

  } catch (err) {
    console.error('Error fetching details:', err);
    // Do not crash, keep showing what we have or blank out
  }
}

async function pollCycle() {
  if (isFetching || document.hidden) return;
  isFetching = true;
  currentSequence++;
  const seq = currentSequence;

  try {
    const [stats, attackers, events] = await Promise.all([
      fetchJson('/api/stats'),
      fetchJson('/api/attackers'),
      fetchJson('/api/events')
    ]);

    if (seq !== currentSequence) return; // Stale

    errorBar.classList.add('hidden');

    renderStats(stats);
    renderAttackers(attackers);
    renderFeed(events);

    if (selectedIp) {
      await fetchSelectedAttackerDetails();
    }
    if (!bansPanel.classList.contains('hidden')) {
      await loadBans();
    }
  } catch (err) {
    if (seq === currentSequence) {
      errorBar.classList.remove('hidden');
    }
  } finally {
    if (seq === currentSequence) {
      isFetching = false;
      // Schedule next poll ONLY after this one finishes
      scheduleNext();
    }
  }
}

function scheduleNext() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(() => {
    pollCycle();
  }, 3000);
}

// Restart cycle immediately if tab becomes visible
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    clearTimeout(pollTimer);
    isFetching = false; // Reset state if it was hung
    pollCycle();
  }
});

const logoutBtn = document.getElementById('logout-btn');
if (logoutBtn) {
  logoutBtn.addEventListener('click', async () => {
    try {
      await fetchJson('/api/logout', { method: 'POST' });
    } catch(err) {}
    window.location.href = '/login.html';
  });
}

function openBanModal(ip) {
  banIpToSubmit = ip;
  banTargetIp.textContent = ip;
  banReason.value = '';
  banHours.value = '24';
  banModal.classList.remove('hidden');
}

function closeBanModal() {
  banModal.classList.add('hidden');
  banIpToSubmit = null;
}

if (cancelBanBtn) cancelBanBtn.addEventListener('click', closeBanModal);
if (confirmBanBtn) confirmBanBtn.addEventListener('click', async () => {
  if (!banIpToSubmit) return;
  try {
    const res = await fetch('/api/bans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify({ ip: banIpToSubmit, reason: banReason.value, hours: parseInt(banHours.value, 10) })
    });
    if (!res.ok) {
      const errData = await res.json().catch(()=>({}));
      showActionMessage(errData.error || 'Failed to ban', false);
      return;
    } else {
      showActionMessage(`Banned ${banIpToSubmit} for ${banHours.value} hour(s)`, true);
    }
  } catch (err) {
    showActionMessage(err.message, false);
    return;
  }
  closeBanModal();
  isFetching = false;
  clearTimeout(pollTimer);
  pollCycle();
});

async function unbanIp(ip) {
  try {
    const res = await fetch(`/api/bans/${encodeURIComponent(ip)}/unban`, {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken }
    });
    if (!res.ok) {
      const errData = await res.json().catch(()=>({}));
      showActionMessage(errData.error || 'Failed to unban', false);
    } else {
      showActionMessage(`Unbanned ${ip}`, true);
      isFetching = false;
      clearTimeout(pollTimer);
      pollCycle();
    }
  } catch (err) {
    showActionMessage(err.message, false);
  }
}

function showError(msg) {
  errorBar.textContent = msg;
  errorBar.classList.remove('hidden');
  setTimeout(() => errorBar.classList.add('hidden'), 5000);
}

let actionTimer = null;
function showActionMessage(msg, isSuccess) {
  if (actionTimer) {
    clearTimeout(actionTimer);
  }
  
  actionBar.className = isSuccess ? 'msg-success' : 'msg-error';
  actionMessage.textContent = msg;
  actionBar.classList.remove('hidden');
  
  actionTimer = setTimeout(() => {
    actionBar.classList.add('hidden');
    actionTimer = null;
  }, 10000);
}

if (closeActionBtn) {
  closeActionBtn.addEventListener('click', () => {
    actionBar.classList.add('hidden');
    clearTimeout(actionTimer);
  });
}

if (showBansBtn) {
  showBansBtn.addEventListener('click', () => {
    bansPanel.classList.remove('hidden');
    loadBans();
  });
}

if (closeBansBtn) {
  closeBansBtn.addEventListener('click', () => {
    bansPanel.classList.add('hidden');
  });
}

async function loadBans() {
  try {
    const bans = await fetchJson('/api/bans');
    renderBans(bans);
  } catch (err) {
    showError('Error loading bans');
  }
}

function renderBans(bans) {
  bansTbody.textContent = '';
  if (!bans || bans.length === 0) {
    const tr = document.createElement('tr');
    tr.className = 'empty-state';
    const td = document.createElement('td');
    td.setAttribute('colspan', '5');
    td.textContent = 'No active bans.';
    tr.appendChild(td);
    bansTbody.appendChild(tr);
    return;
  }
  bans.forEach(b => {
    const tr = document.createElement('tr');
    tr.appendChild(createTableCell(b.ip));
    tr.appendChild(createTableCell(b.reason || ''));
    tr.appendChild(createTableCell(formatDate(b.created_at), b.created_at));
    tr.appendChild(createTableCell(formatDate(b.expires_at), b.expires_at));
    
    const tdAction = document.createElement('td');
    const btn = document.createElement('button');
    btn.textContent = 'Unban';
    btn.addEventListener('click', () => unbanIp(b.ip));
    tdAction.appendChild(btn);
    tr.appendChild(tdAction);
    
    bansTbody.appendChild(tr);
  });
}

// Initial kick-off
checkSession().then(() => {
  if (csrfToken) {
    pollCycle();
  }
});
